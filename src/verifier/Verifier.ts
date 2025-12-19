import { RP } from './RP'
import { Router } from "express";
import { EventEmitter } from "typeorm/platform/PlatformTools";
import { getBaseUrl } from "@utils/getBaseUrl";
import { DIDDocument } from "did-resolver";
import { getPresentationStore, PresentationDefinition } from "presentations/PresentationStore";
import { StatusList } from "statuslist/StatusList";
import { SessionStateManager } from '@utils/SessionStateManager';
import { CryptoKey, Factory } from '@muisit/cryptokey';
import { Identifier } from 'packages/datastore';
import { getDIDConfigurationStore } from 'dids/Store';
import { Session } from 'packages/datastore/entities/Session';

export interface VerifierOptions {
    name:string;
    did:string;
    adminToken:string;
    path:string;
    presentations:string[];
    metadata?: any;
}

export class Verifier {
    public name:string;
    public did:string;
    public identifier?:Identifier|null;
    public adminToken:string;
    public key?:CryptoKey;
    public router:Router|undefined;
    public path:string;
    public eventEmitter:EventEmitter;
    public sessionManager:SessionStateManager;
    public presentations:string[];
    public sessions:Map<string,RP>;
    public statusList:StatusList;
    public metadata?:any;

    public constructor(opts:VerifierOptions)
    {
        this.name = opts.name;
        this.did = opts.did;
        this.adminToken = opts.adminToken;
        this.path = opts.path;
        this.eventEmitter = new EventEmitter();
        this.sessionManager = new SessionStateManager(this.name);
        this.sessions = new Map();
        this.presentations = opts.presentations;
        this.statusList = new StatusList();
        this.metadata = opts.metadata;
    }

    public async initialise() {
        const store = getDIDConfigurationStore();
        if (!this.did) {
            throw new Error('Missing issuer did configuration');
        }

        const keymaterial = await store.get(this.did);
        
        if (!keymaterial?.identifier || !keymaterial.identifier.keys || !keymaterial.key) {
            throw new Error("Missing keys or identifier");
        }
        this.identifier = keymaterial.identifier;
        this.key = keymaterial.key;
    }
    
    public clientId()
    {
        // https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html#section-7.2.3
        return this.identifier!.did; // workaround for UniMe, which only supports the client_id_scheme 'did'
    }

    public basePath()
    {
        return getBaseUrl() + '/' + this.name;
    }

    public async getRPForSession(session:Session): Promise<RP> {
        if (session.data.presentationId) {
            return new RP(this, this.getPresentation(session.data.presentationId)!, session);
        }
        else if(session.data.dcql) {
            return new RP(this, session.data.dcql, session);
        }
        throw new Error("No relying party could be created");
    }

    public signingAlgorithm():string
    {
        return this.key!.algorithms()[0];
    }

    public vpFormats():any {
        return {
            "jwt_vc_json": {
                "alg": ['EdDSA', 'ES256', 'ES256K', 'RS256']
            },
//            "vc+sd-jwt": {
//                "sd-jwt_alg_values": ['EdDSA', 'ES256', 'ES256K', 'RS256']
//            },
//            "dc+sd-jwt": {
//                "sd-jwt_alg_values": ['EdDSA', 'ES256', 'ES256K', 'RS256']
//            }
        };
    }

    public async getDidDoc():Promise<DIDDocument> {
        if (!this.identifier!.did.startsWith('did:web:')) {
            throw new Error("no DID document for non-webbased did");
        }
        const didDoc = await Factory.toDIDDocument(this.key!, this.identifier!.did, [{
            "id": this.identifier!.did + '#oid4vp',
            "type": "OID4VP",
            "serviceEndpoint": getBaseUrl()
        }
        ], "JsonWebKey2020");
    
        return didDoc;
    }

    public getPresentation(presentationId:string): PresentationDefinition|null
    {
        if (this.presentations.includes(presentationId)) {
            const store = getPresentationStore();
            if (store[presentationId]) {
                return Object.assign({}, store[presentationId]);
            }
        }
        return null;
    }
}