import { Verifier } from "./Verifier";
import { PresentationDefinitionV2, PresentationSubmission as PEXPresentationSubmission, JWTVerified } from "externals";
import { AuthorizationRequestPayload, ResponseMode, ResponseType, RPRegistrationMetadataPayload, Scope, SubjectType } from '@sphereon/did-auth-siop'
import { v4 } from 'uuid';
import { SigningAlgo } from "@sphereon/ssi-sdk.siopv2-oid4vp-common";
import { IPresentation } from "@sphereon/ssi-types";
import { IAgent, IKey, IKeyManager } from "@veramo/core";
import { agent, resolver } from 'agent';
import { ExtractedCredential, PresentationSubmission, StatusList } from "./PresentationSubmission";
import { createJWT, verifyJWT } from 'externals';
import { openObserverLog } from "@utils/openObserverLog";
import { Message } from "types";
import { JWTHeader } from "did-jwt";

export enum RPStatus {
    INIT = 'INITIALIZED',
    CREATED = 'AUTHORIZATION_REQUEST_CREATED',
    RETRIEVED = 'AUTHORIZATION_REQUEST_RETRIEVED',
    PROCESSING = 'RESPONSE_PROCESSING',
    RESPONSE = 'RESPONSE_RECEIVED'
}

export interface VPResult {
    issuer?:string;
    credentials?:ExtractedCredential[];
    nonce?:string|undefined;
    state:string|undefined;
    messages:Message[];
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

    public async toJWT(payload:any, type:string):Promise<string> {
        const header = {
            alg: this.verifier.signingAlgorithm(),
            kid: this.verifier.identifier!.did + '#' + this.verifier.key?.kid,
            typ: type
        } as Partial<JWTHeader>;
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
            "client_id": this.verifier.clientId(),
            "client_id_scheme": "did", // UniMe workaround
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
            "id_token_signing_alg_values_supported": [SigningAlgo.EDDSA, SigningAlgo.ES256],
            "request_object_signing_alg_values_supported": [SigningAlgo.EDDSA, SigningAlgo.ES256],
            "response_types_supported": [ResponseType.VP_TOKEN],
            "scopes_supported": [Scope.OPENID],
            "subject_types_supported": [SubjectType.PAIRWISE],
            "subject_syntax_types_supported": ['did:jwk', 'did:key'],
            "vp_formats": this.verifier.vpFormats()
        };
    }

    public async processResponse(state:string, token:string, submission: PEXPresentationSubmission) {
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
            // no need to carry on, the rest of the code only revolves around validating the JWT content, but there is no JWT
            this.status = RPStatus.RESPONSE;
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
                const presentationSubmission = new PresentationSubmission(jwt.payload as IPresentation, this.presentation, submission, this.verifier.did);
                try {
                    const verifyMessages = await presentationSubmission.verify();
                    if (verifyMessages.length > 0) {
                        this.result!.messages = this.result!.messages.concat(verifyMessages);
                    }
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

                for(const credential of this.result.credentials) {
                    const messages = await this.validateStatusLists(credential);

                    if (messages.length > 0) {
                        this.result!.messages = this.result!.messages.concat(messages);
                    }
                }
            }
        }
        this.status = RPStatus.RESPONSE;
        return this.result;
    }

    private async validateStatusLists(credential:ExtractedCredential): Promise<Message[]>
    {
        const retval:Message[] = [];

        if (credential.statusLists && credential.statusLists.length) {
            for (const statusList of credential.statusLists) {
                const message = await this.validateStatusList(statusList);
                if (message.code.length > 0) {
                    retval.push(message);
                }
            }
        }
        else {
            retval.push({code:'NO_STATUS_LIST', message:'Credential does not implement a status list'});
        }

        return retval;
    }

    private async validateStatusList(statusList:StatusList):Promise<Message>
    {
        var retval:Message = {code:'', message:''};
        if (statusList.statusListCredential) {
            try {
                retval = await this.verifier.statusList.checkStatus(statusList.statusListCredential, parseInt(statusList.statusListIndex));
            }
            catch (e) {
                retval.code = 'STATUSLIST_UNREACHABLE';
                retval.message = 'Statuslist could not be retrieved';
            }
        }
        return retval;       
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
