import { Verifier } from "./Verifier";
import { PresentationDefinitionV2, PresentationSubmission as PEXPresentationSubmission, W3CVerifiableCredential, JWTVerified } from "externals";
import {
    AuthorizationRequestPayload,
    ClientMetadataOpts,
    InMemoryRPSessionManager,
    PassBy,
    PropertyTarget,
    ResponseMode,
    ResponseType,
    RevocationVerification,
    RPRegistrationMetadataPayload,
    Scope,
    SIOPErrors,
    SubjectType,
    SupportedVersion,
    VerifiedJWT,
    VerifyJwtCallback,
} from '@sphereon/did-auth-siop'
import { v4 } from 'uuid';
import { SigningAlgo } from "@sphereon/ssi-sdk.siopv2-oid4vp-common";
import { IPresentation } from "@sphereon/ssi-types";
import { IAgent, IKey, IKeyManager } from "@veramo/core";
import { agent, resolver } from 'agent';
import { ExtractedCredential, PresentationSubmission } from "./PresentationSubmission";
import { createJWT, verifyJWT } from 'externals';
import { openObserverLog } from "@utils/openObserverLog";

export enum RPStatus {
    INIT = 'INITIALIZED',
    CREATED = 'AUTHORIZATION_REQUEST_CREATED',
    RETRIEVED = 'AUTHORIZATION_REQUEST_RETRIEVED',
    RESPONSE = 'RESPONSE_RECEIVED'
}

export interface VPResultMessage {
    code: string;
    message: string;
    [x:string]: any;
}

export interface VPResult {
    issuer?:string;
    credentials?:ExtractedCredential[];
    nonce?:string|undefined;
    state:string|undefined;
    messages:VPResultMessage[];
}

export class RP {
    public verifier:Verifier;
    public presentation:PresentationDefinitionV2;

    // session state values
    public authorizationRequest:AuthorizationRequestPayload|undefined;
    public jwt:string|undefined;
    public state:string|undefined;
    public nonce:string|undefined;
    public status:RPStatus = RPStatus.INIT;
    public created:Date;
    public lastUpdate:Date;
    public result:VPResult|undefined;

    public constructor(v:Verifier, p:PresentationDefinitionV2) {
        this.verifier = v;
        this.presentation = p;
        this.created = new Date();
        this.lastUpdate = new Date();
    }

    public async toJWT(payload:any):Promise<string> {
        const header = {
            alg: this.verifier.signingAlgorithm(),
            kid: this.verifier.key
          };
        this.jwt = await createJWT(
            payload,
            {
                issuer: this.verifier.identifier!.did,
                signer: wrapSigner(agent, this.verifier.key!, this.verifier.signingAlgorithm()),
                expiresIn: 10  *60,
                canonicalize: false
            },
            header);
        this.lastUpdate = new Date();
        return this.jwt!;
    }

    public createAuthorizationRequest(responseUri: string, presentationUri:string, state:string):AuthorizationRequestPayload {
        this.status = RPStatus.CREATED;
        this.nonce = v4();
        this.authorizationRequest = {
            // basic RequestObject attributes
            "scope": Scope.OPENID,
            "response_type": ResponseType.VP_TOKEN,
            "client_id": responseUri, // required according to the spec
            //"client_id_scheme": ...
            //"redirect_uri": redirectUri,
            "response_uri": responseUri,
            "nonce": this.nonce,
            "state": state,

            // AuthorizationRequest attributes
            "response_mode": ResponseMode.DIRECT_POST, // default is using query or fragment elements in the callback
            "client_metadata": this.clientMetadata(),
            "presentation_definition_uri": presentationUri,
        };
        this.lastUpdate = new Date();
        return this.authorizationRequest;
    }

    private clientMetadata():RPRegistrationMetadataPayload {
        return {
            "id_token_signing_alg_values_supported": [SigningAlgo.EDDSA, SigningAlgo.ES256, SigningAlgo.ES256K],
            "request_object_signing_alg_values_supported": [SigningAlgo.EDDSA, SigningAlgo.ES256, SigningAlgo.ES256K],
            "response_types_supported": [ResponseType.VP_TOKEN],
            "scopes_supported": [Scope.OPENID],
            "subject_types_supported": [SubjectType.PAIRWISE],
            "subject_syntax_types_supported": ['did:web', 'did:jwk', 'did:key', 'did:ion'],
            "vp_formats": this.verifier.vpFormats()
        };
    }

    public async processResponse(state:string, token:string, submission: PEXPresentationSubmission) {
        // whatever happens, our state switches to RESPONSE to indicate we received something
        this.status = RPStatus.RESPONSE;

        this.result = {
            state: state,
            messages: []
        }

        if (this.state != state) {
            console.log("state is ", this.state, state);
            this.result.messages.push({
                code: 'INVALID_STATE',
                message: 'Verifier states did not match',
                expectedState: this.state,
                receivedState: state
            });
            return this.result;
        }

        var jwt:JWTVerified|null = null;
        try {
            jwt = await verifyJWT(
                token,
                {
                    resolver: resolver,
                    audience: this.authorizationRequest?.client_id
                });
            if (!jwt) {
                throw new Error("no JWT found");
            }
        }
        catch (e:any) {
            this.result!.messages.push({
                code: 'INVALID_JWT',
                message: 'Response JWT is corrupt',
                error: e,
                jwt: token
            });
            return this.result;
        }

        if (jwt !== null) {
            this.result.issuer = jwt.issuer;
            this.result.nonce = jwt.payload.nonce;
            openObserverLog(state, 'receive-response', { name: this.verifier.name, request: jwt});

            if (!jwt.verified) {
                this.result!.messages.push({
                    code: 'UNVERIFIED_JWT',
                    message: 'Could not verify JWT token',
                    jwt: token,
                    signer: jwt.signer,
                    issuer: jwt.issuer,
                    payload: jwt.payload
                });
            }

            if (!jwt.payload.verifiableCredential || !Array.isArray(jwt.payload.verifiableCredential)) {
                this.result!.messages.push({
                    code: 'NO_CREDENTIALS_FOUND',
                    message: 'Decoded JWT does not contain credentials',
                    payload: jwt.payload
                });
            }

            if (jwt.payload.nonce != this.nonce) {
                this.result!.messages.push({
                    code: 'INVALID_NONCE',
                    message: 'Nonce value of JWT does not match expected value',
                    expectedNonce: this.nonce,
                    receivedNonce: jwt.payload.nonce
                });
            }

            if (jwt.payload.verifiableCredential && Array.isArray(jwt.payload.verifiableCredential)) {
                const presentationSubmission = new PresentationSubmission(jwt.payload as IPresentation, this.presentation, submission);
                try {
                    await presentationSubmission.verify();
                }
                catch (e) {
                    this.result!.messages.push({
                        code: 'INVALID_PRESENTATION',
                        message: 'Validation of presentation failed',
                        error: e
                    });
                }
                openObserverLog(state, 'receive-response', { name: this.verifier.name, presentation: presentationSubmission});
                this.result.credentials = presentationSubmission.credentials;
            }
        }
        return this.result;
    }
}

function wrapSigner(
    agent:IAgent & IKeyManager,
    key: IKey,
    algorithm?: string,
  ) {
    return async (data: string | Uint8Array): Promise<string> => {
      const result = await agent.keyManagerSign({ keyRef: key.kid, data: <string>data, algorithm })
      return result
    }
  }