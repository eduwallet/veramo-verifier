import { Verifier } from "./Verifier";
import { PresentationDefinitionV2, PresentationSubmission as PEXPresentationSubmission, W3CVerifiableCredential } from "externals";
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

export interface VPResult {
    issuer: string;
    credentials:ExtractedCredential[];
    nonce: string|undefined;
    state: string|undefined;
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
        if (this.state != state) {
            console.log("state is ", this.state, state);
            throw new Error("invalid state");
        }

        const jwt = await verifyJWT(
            token,
            {
                resolver: resolver,
                audience: this.authorizationRequest?.client_id
            });
        openObserverLog(state, 'receive-response', { name: this.verifier.name, request: jwt});

        if (!jwt.verified || !jwt.payload.verifiableCredential || !Array.isArray(jwt.payload.verifiableCredential)) {
            throw new Error("Invalid vp_token");
        }

        if (jwt.payload.nonce != this.nonce) {
            throw new Error("Invalid encoding of nonce");
        }

        const presentationSubmission = new PresentationSubmission(jwt.payload as IPresentation, this.presentation, submission);
        const submissionCheck = await presentationSubmission.verify();
        if (!submissionCheck) {
            throw new Error("Invalid presentation submission");
        }

        openObserverLog(state, 'receive-response', { name: this.verifier.name, presentation: presentationSubmission});
        this.result = {
            issuer: jwt.issuer,
            nonce: jwt.payload.nonce,
            state: state,
            credentials: presentationSubmission.credentials
        }
        this.status = RPStatus.RESPONSE;
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