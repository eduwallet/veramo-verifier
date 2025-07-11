import { Verifier } from "./Verifier";
import { v4 } from 'uuid';
import { ExtractedCredential, PresentationSubmission, StatusList } from "./PresentationSubmission";
import { Message } from "types";
import { PresentationDefinition } from "presentations/PresentationStore";
import { Factory } from "@muisit/cryptokey/*";
import { JWT } from "@muisit/simplejwt";
import { AuthorizationRequest } from "types/authrequest";
import { AuthorizationResponse, PresentationResult } from "types/authresponse";

export enum RPStatus {
    INIT = 'INITIALIZED',
    CREATED = 'AUTHORIZATION_REQUEST_CREATED',
    RETRIEVED = 'AUTHORIZATION_REQUEST_RETRIEVED',
    PROCESSING = 'RESPONSE_PROCESSING',
    RESPONSE = 'RESPONSE_RECEIVED'
}

interface Credentials {
    [x:string]: ExtractedCredential[];
}

export interface VPResult {
    issuer?:string;
    credentials?:Credentials;
    nonce?:string|undefined;
    state:string|undefined;
    messages:Message[];
}

export class RP {
    public verifier:Verifier;
    public presentation:PresentationDefinition;

    // session state values
    public authorizationRequest?:any;
    public jwt:string|undefined;
    public state:string|undefined;
    public nonce:string|undefined;
    public status:RPStatus = RPStatus.INIT;
    public created:Date;
    public lastUpdate:Date;
    public result:VPResult|undefined;

    public constructor(v:Verifier, p:PresentationDefinition) {
        this.verifier = v;
        this.presentation = p;
        this.created = new Date();
        this.lastUpdate = new Date();
    }

    public async toJWT(payload:any, type:string):Promise<string> {
        const jwt = new JWT();
        jwt.header = {
            alg: this.verifier.signingAlgorithm(),
            kid: this.verifier.did + '#' + Factory.getKeyReference(this.verifier.did),
            typ: type
        };
        jwt.payload = payload;

        // https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html#section-9.1
        // "The aud Claim MUST equal to the issuer Claim value, when Dynamic Self-Issued OP Discovery is performed."
        jwt.payload!.aud = this.verifier.clientId();

        jwt.sign(this.verifier.key!);
        this.lastUpdate = new Date();
        this.jwt = jwt.token;
        return this.jwt;
    }

    public createAuthorizationRequest(responseUri: string, state:string): AuthorizationRequest {
        this.status = RPStatus.CREATED;
        this.nonce = v4();
        this.authorizationRequest = {
            // basic RequestObject attributes
            "response_type": 'vp_token id_token', // instructs the wallet to return a vp_token response with a SIOP id_token
            "response_mode": "direct_post", // default is using query or fragment elements in the callback
            "state": state,
            // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-5.9.3
            // use the decentralized_identifier prefix to pass on our did key
            "client_id": 'decentralized_identifier:' + this.verifier.clientId(),
            //"scope": // used for predefined dcql queries
            // https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html#section-9.2
            // "This endpoint to which the Self-Issued OP shall deliver the authentication result is conveyed in the standard parameter redirect_uri."
            "redirect_uri": responseUri,
            "client_id_scheme": "did", // UniMe workaround
            // https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html#section-9
            // "The RP MUST send a nonce"
            "nonce": this.nonce,

            // AuthorizationRequest attributes
            // https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html#section-9
            "client_metadata": this.clientMetadata(),
            "id_token_type": "attester_signed_id_token subject_signed_id_token",
            "dcl_query": this.presentation.query,
        };
        this.lastUpdate = new Date();
        return this.authorizationRequest;
    }

    private clientMetadata() {
        return {
            "id_token_signing_alg_values_supported": ['EdDSA','ES256', 'ES256K', 'RS256'],
            "request_object_signing_alg_values_supported": ['EdDSA','ES256', 'ES256K', 'RS256'],
            "response_types_supported": ['token'],
            //"scopes_supported": [Scope.OPENID],
            "subject_types_supported": ['pairwise'],
            // https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html#section-7.5
            "subject_syntax_types_supported": ['did:jwk', 'did:key'],
            "vp_formats": this.verifier.vpFormats()
        };
    }

    public async parseIDToken(token:string)
    {
        // this implements parsing the SIOPv2 id_token
        let jwt:JWT;
        try {
            jwt = JWT.fromToken(token);
            // should not occur
            if (!jwt) {
                return false;
            }
        }
        catch (e) {
            this.result!.messages.push({
                code: 'INVALID_JWT',
                message: 'Could not decode JWT',
                jwt: token
            });
            return false;
        }

        // https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html#section-11
        // iss and sub must be equal
        if (!jwt.payload?.iss || !jwt.payload?.sub || jwt.payload.iss != jwt.payload.sub) {
            this.result!.messages.push({
                code: 'INVALID_JWT',
                message: 'iss and sub claims invalid',
                jwt: token
            });
            return false;
        }
        else {
            const skey = await Factory.resolve(jwt.payload!.iss);
            if (!skey) {
                this.result!.messages.push({
                    code: 'INVALID_JWT',
                    message: 'Could not find a signing key',
                    jwt: token
                });
                return false;
            }
            else {
                if (!jwt.verify(skey)) {
                    this.result!.messages.push({
                        code: 'INVALID_JWT',
                        message: 'Signature could not be validated',
                        jwt: token
                    });
                    return false;
                }
            }
        }
        this.result!.issuer = jwt.payload!.iss;
        return true;
    }

    public async processResponse(state:string, response:AuthorizationResponse, submission: any) {
        // whatever happens, our state switches to RESPONSE to indicate we received something
        this.status = RPStatus.PROCESSING;

        this.result = {
            state: state,
            messages: []
        }

        if (this.state != state) {
            this.result.messages.push({
                code: 'INVALID_STATE',
                message: 'Verifier states did not match',
                expectedState: this.state,
                receivedState: state
            });
            // no need to proceed further, something really bad is going on and the content
            // of the response simply cannot be trusted at all
            this.status = RPStatus.RESPONSE;
            return this.result;
        }

        // we expect an id_token in the response to signal the wallet holder key
        if (!response.id_token)
        {
            this.result!.messages.push({
                code: 'INVALID_RESPONSE',
                message: 'Missing id_token'
            });
            this.status = RPStatus.RESPONSE;
            return this.result;
        }
        else {
            if(!this.parseIDToken(response.id_token)) {
                this.status = RPStatus.RESPONSE;
                return this.result;
            }
        }

        this.parseVPToken(response.vp_token);
        this.status = RPStatus.RESPONSE;
        return this.result;
    }

    private parseVPToken(vptoken:PresentationResult) 
    {
        this.status = RPStatus.RESPONSE;
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-8.1
        //  vp_token: REQUIRED. This is a JSON-encoded object containing entries where the key is the id value used for a Credential Query in the DCQL query and the value is an array of one or more Presentations that match the respective Credential Query. 
        if (!vptoken || Object.keys(vptoken).length == 0) {
            this.result!.messages.push({
                code: 'NO_CREDENTIALS_FOUND',
                message: 'Response does not contain credentials',
                payload: vptoken
            });
            return this.result;
        }

        this.result!.credentials = {};
        for (const presId of this.presentation.query.credentials) {
            const submission = new PresentationSubmission(this, presId, this.presentation.query.credentials[presId], vptoken[presId]);

            if (!submission.validate()) {
                this.result!.messages.push({
                    code: 'INVALID_CREDENTIAL_FOUND',
                    message: 'Credential presentation ' + presId +' could not be validated',
                    payload: vptoken
                });
            }

            this.result!.credentials[presId] = submission.credentials;
        }
        return this.result;
    }
}