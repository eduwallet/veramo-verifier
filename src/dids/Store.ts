import Debug from 'debug';
const debug = Debug('issuer:did');
/*
 * Instantiate context configurations
 */

import { loadJsonFiles } from "#root/utils/loadJsonFiles";
import { Identifier, Key, PrivateKey } from "#root/database/entities/index";
import { CryptoKey, Factory } from '@muisit/cryptokey';
import { getDbConnection } from '#root/database/index';
import { resolveConfPath } from '@utils/resolveConfPath';

export interface DIDStoreValue {
    identifier: Identifier;
    key:CryptoKey;
    path?:string;
    service?:any;
}

export interface DIDConfiguration {
    did?: string
    alias?: string;
    path?:string;
    service?:any;
    type: string;
    provider: string;
    identifier: Identifier;
    key:CryptoKey;
}

interface DIDStoreValues {
  [x:string]: DIDStoreValue;
}

class DIDConfigurationStore {
    private configuration:DIDStoreValues = {};

    public async init()
    {
        try {
            const path = resolveConfPath('dids');
            debug('Loading DID configurations, path: ' + path);
            const configurations = loadJsonFiles<DIDConfiguration>({ path });
            for (const key of Object.keys(configurations.asObject)) {
                var cfg = configurations.asObject[key];
                await this.add(key, cfg);
            }
        }
        catch (e) {
            debug("Missing path for DIDs");
        }
    }

    public async add(key:string, configuration:DIDConfiguration)
    {
        const dbConnection = getDbConnection();
        const ids = dbConnection.getRepository(Identifier);
        const result = await ids.createQueryBuilder('identifier')
            .innerJoinAndSelect("identifier.keys", "key")
            .where('identifier.did=:did', {did: configuration.did})
            .orWhere('identifier.alias=:alias', {alias: configuration.alias})
            .getOne();
        
        let value:DIDStoreValue|null = null;
        if (!result) {
            value = await this.initialiseKey(configuration);
        }
        else {
            value = await this.initialiseDBKey(result);
        }

        this.configuration[key] = value;
    }

    private async initialiseDBKey(result:Identifier): Promise<DIDStoreValue>
    {
        const dbConnection = getDbConnection();
        const dbKey = result.keys[0];
        const pkeys = dbConnection.getRepository(PrivateKey);
        const pkey = await pkeys.findOneBy({alias:dbKey.kid});
        const decodedPkey = await pkey!.decodeKey();
        const ckey = await Factory.createFromType(dbKey.type, decodedPkey);
        return {
            identifier: result,
            key: ckey
        };
    }

    private async initialiseKey(configuration:DIDConfiguration): Promise<DIDStoreValue>
    {
        const kType = configuration.type || 'Secp256r1';
        const ckey = await Factory.createFromType(kType);
        await ckey.createPrivateKey();

        const identifier = new Identifier();
        switch (configuration.provider) {
            case 'did:web':
                if (!configuration.did || configuration.did.length == 0) {
                    throw new Error("No did specified for did:web key");
                }
                identifier.did = configuration.did;
                break;
            case 'did:key':
                identifier.did = await Factory.toDIDKey(ckey);
                break;
            default: // DIIPv4 uses did:jwk by default
            case 'did:jwk':
                identifier.did = await Factory.toDIDJWK(ckey);
                break;
        }
        identifier.alias = configuration.alias ?? configuration.did;
        identifier.provider = configuration.provider ?? 'did:jwk';
        identifier.controllerKeyId = ckey.exportPublicKey();

        const dbConnection = getDbConnection();
        const irepo = dbConnection.getRepository(Identifier);
        await irepo.save(identifier);

        const dbKey = new Key();
        dbKey.kid = ckey.exportPublicKey();
        dbKey.kms = 'local';
        dbKey.type = ckey.keyType;
        dbKey.publicKeyHex = dbKey.kid;
        dbKey.identifier = identifier;
        const krepo = dbConnection.getRepository(Key);
        await krepo.save(dbKey);

        const pKey = new PrivateKey();
        pKey.alias = dbKey.kid;
        pKey.type = dbKey.type;
        pKey.setSeed();
        await pKey.encodeKey(ckey.exportPrivateKey());
        const prepo = dbConnection.getRepository(PrivateKey);
        await prepo.save(pKey);

        return {
            identifier,
            key:ckey
        };
    }

    public keys() {
        return Object.keys(this.configuration);
    }

    public async keysWithPath() {
        const dbConnection = getDbConnection();
        const irepo = dbConnection.getRepository(Identifier);
        const keys = await irepo.createQueryBuilder('identifier')
            .where('not identifier.path is NULL')
            .where("identifier.path <> ''")
            .getMany();
        return keys.map((i:Identifier) => i.did);
    }
    
    public async get(key:string) {
        if (this.configuration[key]) {
            return this.configuration[key];
        }
        const dbConnection = getDbConnection();
        const ids = dbConnection.getRepository(Identifier);
        const result = await ids.createQueryBuilder('identifier')
            .innerJoinAndSelect("identifier.keys", "key")
            .where('identifier.did=:did', {did: key})
            .orWhere('identifier.alias=:alias', {alias: key})
            .getOne();
        if (result && result.did) {
            const value = await this.initialiseDBKey(result);
            this.configuration[key] = value;
            return value;
        }
        return null;
    }
}

var _didConfigurationStore: DIDConfigurationStore = new DIDConfigurationStore();
export const getDIDConfigurationStore = (): DIDConfigurationStore => _didConfigurationStore;
