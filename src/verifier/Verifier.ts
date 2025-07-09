import { RP } from './RP'
import { Router } from "express";
import { EventEmitter } from "typeorm/platform/PlatformTools";
import { getBaseUrl } from "@utils/getBaseUrl";
import { DIDDocument } from "did-resolver";
import { getPresentationStore, PresentationDefinition } from "presentations/PresentationStore";
import { StatusList } from "statuslist/StatusList";
import { SessionStateManager } from '@utils/SessionStateManager';
import { CryptoKey, Factory } from '@muisit/cryptokey/*';
import { getDbConnection } from 'database';
import { Identifier, PrivateKey } from 'packages/datastore';

export interface VerifierOptions {
    name:string;
    did:string;
    adminToken:string;
    path:string;
    presentations:string[];
}

interface RPSessions {
    [x:string]: RP;
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
    public sessions:RPSessions = {};
    public statusList:StatusList;

    public constructor(opts:VerifierOptions)
    {
        this.name = opts.name;
        this.did = opts.did;
        this.adminToken = opts.adminToken;
        this.path = opts.path;
        this.eventEmitter = new EventEmitter();
        this.sessionManager = new SessionStateManager();
        this.presentations = opts.presentations;
        this.statusList = new StatusList();
    }

    public async initialise() {
        const dbConnection = await getDbConnection();
        const ids = dbConnection.getRepository(Identifier);
        this.identifier = await ids.createQueryBuilder('identifier')
            .innerJoinAndSelect("identifier.keys", "key")
            .where('did=:did', {did: this.did})
            .orWhere('alias=:alias', {alias: this.did})
            .getOne();
        
        if (!this.did) {
            throw new Error('Missing issuer did configuration');
        }
        const dbKey = this.identifier!.keys[0];
        const pkeys = dbConnection.getRepository(PrivateKey);
        const pkey = await pkeys.findOneBy({alias:dbKey.kid});

        this.key = await Factory.createFromType(dbKey.type, pkey?.privateKeyHex);

    }
    
    public clientId()
    {
        return this.did; // workaround for UniMe, which only supports the client_id_scheme 'did'
    }

    public basePath()
    {
        return getBaseUrl() + '/' + this.name;
    }

    public getRPForPresentation(presentationId:string, state:string): RP {
        const rp = new RP(this, this.getPresentation(presentationId)!);
        this.sessions[state] = rp;
        rp.state = state;
        return rp;
    }

    public signingAlgorithm():string
    {
        return this.key!.algorithms()[0];
    }

    public vpFormats():any {
        return {
            "jwt_vc": {
                "alg": ['EdDSA', 'ES256', 'ES256K', 'RS256']
            },
            "jwt_vp": {
                "alg": ['EdDSA', 'ES256', 'ES256K', 'RS256']
            }
        };
    }

    public async getDidDoc():Promise<DIDDocument> {
        if (!this.did.startsWith('did:web:')) {
            throw new Error("no DID document for non-webbased did");
        }
        const didDoc = await Factory.toDIDDocument(this.key!, this.did, [{
            "id": this.did + '#oid4vp',
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
                // add the Verifier allowed VP formats explicitely to the presentation
                // formats
                var presentation = Object.assign({}, store[presentationId]);
                //presentation.format = this.vpFormats();
                return presentation;
            }
        }
        return null;
    }
}