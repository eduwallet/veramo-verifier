import { Verifier } from "./Verifier";
import { v4 } from 'uuid';
import { DCQLSubmission, ExtractedCredential } from "./DCQLSubmission";
import { DCQL, Message } from "types";
import { PresentationDefinition } from "presentations/PresentationStore";
import { Factory } from "@muisit/cryptokey";
import { JWT } from "@muisit/simplejwt";
import { AuthorizationRequest } from "types/authrequest";
import { AuthorizationResponse, Presentation, PresentationResult } from "types/authresponse";
import { createRequest_v28 } from "./createRequest_v28";
import { createRequest_v25 } from "./createRequest_v25";
import { PresentationSubmission } from "./PresentationSubmission";
import { Session } from "packages/datastore/entities/Session";

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
    nonce?:string;
    state?:string;
    messages:Message[];
}

export class RP {
    public verifier:Verifier;
    public presentation?:PresentationDefinition;
    public dcql?:DCQL;
    public session:Session;

    public constructor(v:Verifier, p:PresentationDefinition|DCQL, s:Session) {
        this.verifier = v;
        if (p && (p as PresentationDefinition).id && typeof(p) == 'object') {
            this.presentation = p as PresentationDefinition;
        }
        else if (p && (p as DCQL).credentials) {
            this.dcql = p as DCQL;
        }
        this.session = s;
        if (!s.data.created) {
            s.data.created = new Date();
            s.data.lastUpdate = new Date();
        }
        if (!this.session.data.result) {
            this.session.data.result = {
                messages:[]
            };
        }
    }

    public async toJWT(payload:any, type:string, wallet_nonce?:string):Promise<string> {
        const jwt = new JWT();
        jwt.header = {
            alg: this.verifier.signingAlgorithm(),
            kid: this.verifier.identifier!.did + '#' + Factory.getKeyReference(this.verifier.identifier!.did),
            typ: type
        };
        jwt.payload = payload;

        if (wallet_nonce) {
            jwt.payload!.wallet_nonce = wallet_nonce;
        }

        await jwt.sign(this.verifier.key!);
        this.session.data.lastUpdate = new Date();
        return jwt.token;
    }

    public createAuthorizationRequest(): AuthorizationRequest {
        this.session.data.status = RPStatus.CREATED;
        this.session.data.nonce = v4();
        if (this.dcql) {
            this.session.data.authorizationRequest = createRequest_v28(this, this.dcql);
        }
        else if (this.presentation?.query) {
            this.session.data.authorizationRequest = createRequest_v28(this, this.presentation.query);
        }
        else if (this.presentation?.input_descriptors) {
            this.session.data.authorizationRequest = createRequest_v25(this);
        }
        else {
            console.error("dcql", this.dcql);
            console.error("presentation", this.presentation);
            throw new Error("missing query values");
        }
        this.session.data.lastUpdate = new Date();
        return this.session.data.authorizationRequest;
    }

    public clientMetadata() {
        return Object.assign({}, {
            // https://www.rfc-editor.org/rfc/rfc7591.html#section-2
            "client_name": this.presentation?.name ?? this.verifier.name,
            "id_token_signing_alg_values_supported": ['EdDSA','ES256', 'ES256K', 'RS256'],
            "request_object_signing_alg_values_supported": ['EdDSA','ES256', 'ES256K', 'RS256'],
            "response_types_supported": ['vp_token'], // , 'id_token',
            //"scopes_supported": [Scope.OPENID],
            "subject_types_supported": ['pairwise'],
            // https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html#section-7.5
            "subject_syntax_types_supported": ['did:jwk', 'did:key'],
            "vp_formats": this.verifier.vpFormats()
        }, this.verifier.metadata ?? {});
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
            this.session.data.result!.messages.push({
                code: 'INVALID_JWT',
                message: 'Could not decode JWT',
                jwt: token
            });
            return false;
        }

        // https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html#section-11
        // iss and sub must be equal
        // TODO: Sphereon only sends iss, not sub....
        if (jwt.payload?.iss && jwt.payload?.sub && jwt.payload.iss != jwt.payload.sub) {
            this.session.data.result!.messages.push({
                code: 'INVALID_JWT',
                message: 'iss and sub claims invalid',
                jwt: token
            });
            return false;
        }
        else {
            const skey = await Factory.resolve(jwt.payload!.iss);
            if (!skey) {
                this.session.data.result!.messages.push({
                    code: 'INVALID_JWT',
                    message: 'Could not find a signing key',
                    jwt: token
                });
                return false;
            }
            else {
                if (!jwt.verify(skey)) {
                    this.session.data.result!.messages.push({
                        code: 'INVALID_JWT',
                        message: 'Signature could not be validated',
                        jwt: token
                    });
                    return false;
                }
            }
        }
        this.session.data.result!.issuer = jwt.payload!.iss;
        return true;
    }

    public async processResponse(state:string, response:AuthorizationResponse) {
        // whatever happens, our state switches to RESPONSE to indicate we received something
        this.session.data.status = RPStatus.PROCESSING;

        this.session.data.result = {
            state: state,
            messages: []
        }

        if (this.session.uuid != state) {
            this.session.data.result.messages.push({
                code: 'INVALID_STATE',
                message: 'Verifier states did not match',
                expectedState: this.session.uuid,
                receivedState: state
            });
            // no need to proceed further, something really bad is going on and the content
            // of the response simply cannot be trusted at all
            this.session.data.status = RPStatus.RESPONSE;
            return this.session.data.result;
        }

        // we expect an id_token in the response to signal the wallet holder key
        if (!response.id_token)
        {
            this.session.data.result!.messages.push({
                code: 'INVALID_RESPONSE',
                message: 'Missing id_token'
            });
        }
        else {
            if(!await this.parseIDToken(response.id_token)) {
                this.session.data.result!.messages.push({
                    code: 'INVALID_ID_TOKEN',
                    message: 'Could not parse and validate ID token',
                    payload: response.id_token
                });
                }
        }

        if (response.vp_token) {
            await this.parseVPToken(JSON.parse(response.vp_token));
        }
        else {
            this.session.data.result!.messages.push({
                code: 'INVALID_RESPONSE',
                message: 'Missing vp_token'
            });
        }
        this.session.data.status = RPStatus.RESPONSE;
        return this.session.data.result;
    }

    private async parseVPToken(vptoken:PresentationResult) 
    {
        if (this.dcql || this.presentation?.query) {
            return await this.parseDCQLToken(vptoken, this.dcql ?? this.presentation.query);
        }
        else {
            return await this.parsePresentation(vptoken as unknown as Presentation);
        }
    }

    private async parseDCQLToken(vptoken:PresentationResult, query:DCQL)
    {
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-8.1
        //  vp_token: REQUIRED. This is a JSON-encoded object containing entries where the key is the id value used for a Credential Query in the DCQL query and the value is an array of one or more Presentations that match the respective Credential Query. 
        if (!vptoken || Object.keys(vptoken).length == 0) {
            this.session.data.result!.messages.push({
                code: 'NO_CREDENTIALS_FOUND',
                message: 'Response does not contain credentials',
                payload: vptoken
            });
            return;
        }

        this.session.data.result!.credentials = {};
        for (const presentation of query.credentials) {
            const submission = new DCQLSubmission(this, query, presentation, vptoken[presentation.id]);

            await submission.validate();
            if (submission.messages.length) {
                this.session.data.result!.messages = this.session.data.result!.messages.concat(submission.messages);
            }

            this.session.data.result!.credentials[presentation.id] = submission.credentials;
        }
        return this.session.data.result;
    }

    private async parsePresentation(vptoken:Presentation)
    {
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0-22.html#section-7.1
        // vp_token: REQUIRED. 
        // In case Presentation Exchange was used, it is a JSON String or JSON object that MUST contain a single
        // Verifiable Presentation or an array of JSON Strings and JSON objects each of them containing a
        // Verifiable Presentations. Each Verifiable Presentation MUST be represented as a JSON string (that is a
        // base64url-encoded value) or a JSON object depending on a format as defined in Appendix A of OpenID4VCI
        if (!vptoken) {
            this.session.data.result!.messages.push({
                code: 'NO_CREDENTIALS_FOUND',
                message: 'Response does not contain credentials',
                payload: vptoken
            });
            return;
        }

        let tokens:string[] = vptoken as string[];
        if (!Array.isArray(tokens) && typeof(vptoken) == 'string') {
            tokens = [vptoken];
        }
        this.session.data.result!.credentials = {};
        for (const token of tokens) {
            const submission = new PresentationSubmission(this, token);

            await submission.validate();
            if (submission.messages.length) {
                this.session.data.result!.messages = this.session.data.result!.messages.concat(submission.messages);
            }

            this.session.data.result!.credentials[submission.id] = submission.credentials;
        }
    }
}