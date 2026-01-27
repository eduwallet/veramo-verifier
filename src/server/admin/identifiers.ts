import Debug from 'debug';
const debug = Debug('server:api');

import { getDbConnection } from '#root/database/index';
import { Identifier, Key, PrivateKey } from "#root/database/entities/index";
import { Request, Response } from 'express'
import { DataList, identifierToScheme } from './types.js';
import { CryptoKey, Factory } from '@muisit/cryptokey';

export async function listIdentifiers(request: Request, response: Response) {
    try {
        debug('listing identifier');
        const data:DataList = {
            offset: 0,
            count: 0,
            pagesize: 50,
            data: []
        };
        const dbConnection = getDbConnection();
        const ids = dbConnection.getRepository(Identifier);
        const identifiers =  await ids.createQueryBuilder('identifier').orderBy("identifier.did").getMany();
        data.count = identifiers.length;
        for (const id of identifiers) {
            data.data.push(await identifierToScheme(id));
        }

        return response.status(200).json(data);
    }
    catch (e) {
        response.header('Content-Type', 'application/json')
        return response.status(500).json({"error": JSON.stringify(e)});
    }
}

function is_valid_provider(p:string) {
    if (!['did:web', 'did:jwk', 'did:key'].includes(p)) {
        debug("invalid provider selected, returning error");
        throw new Error ('Invalid provider selected');
    }
}

function is_valid_key(k:string)
{
    if (!['Secp256r1','Secp256k1', 'Ed25519', 'RSA'].includes(k)) {
        debug("invalid keytype detected, returning error");
        throw new Error('Invalid key type selected');
    }
}


interface StoreIdentifierRequest {
    did:string;
    original:string;
    alias:string;
    provider:string;
    path?:string;
    services?:string;
}

async function setIdentifierData(identifier:Identifier, did:string, alias:string, provider:string, path?:string, services?:string, ckey:CryptoKey)
{
    identifier.alias = alias;
    identifier.provider = provider;
    identifier.path = path && path.length ? path : undefined;
    identifier.services = services && services.length ? services : undefined;

    switch (identifier.provider) {
        case 'did:web':
            if (!did.startsWith('did:web:') || did.length < 10) {
                throw new Error("Invalid did set for did:web identifier");
            }
            identifier.did = did;
            break;
        case 'did:key':
            identifier.did = await Factory.toDIDKey(ckey);
            break;
        default: // DIIPv4 uses did:jwk by default
        case 'did:jwk':
            identifier.did = await Factory.toDIDJWK(ckey);
            break;
    }
    identifier.controllerKeyId = ckey.exportPublicKey();
}

export async function storeIdentifier(request: Request<StoreIdentifierRequest>, response: Response) {
    try {
        debug("storing identifier", request.body);
        is_valid_provider(request.body.provider);

        const dbConnection = getDbConnection();
        const ids = dbConnection.getRepository(Identifier);
        const identifier =  await ids.createQueryBuilder('identifier')
            .innerJoinAndSelect("identifier.keys", "key")
            .where('did=:did', {did: request.body.original})
            .getOne();
        if (!identifier) {
            throw new Error("Identifier not found for POST");
        }

        const dbKey = identifier.keys[0];
        const pkeys = dbConnection.getRepository(PrivateKey);
        const pkey = await pkeys.findOneBy({alias:dbKey.kid});
        const ckey = await Factory.createFromType(dbKey.type, pkey?.privateKeyHex);

        await setIdentifierData(identifier, request.body.did, request.body.alias, request.body.provider, request.body.path, request.body.services, ckey);

        debug("saving identifier", identifier);
        await ids.save(identifier);

        if (request.body.original !== request.body.did) {
            // in this case, the save above created a new entry referring to the same key.
            await ids.delete({did: request.body.original});
        }

        return response.status(200).json(await identifierToScheme(identifier));
    }
    catch (e) {
        debug("storeIdentifier: caught", e);
        response.header('Content-Type', 'application/json')
        return response.status(500).json({"error": JSON.stringify(e)});
    }
}

interface CreateIdentifierRequest {
    did:string;
    alias:string;
    provider:string;
    path?:string;
    services?:string;
    keytype:string;
}
export async function createIdentifier(request: Request<CreateIdentifierRequest>, response: Response) {
    try {
        is_valid_provider(request.body.provider);
        is_valid_key(request.body.keytype ?? '');

        const dbConnection = getDbConnection();
        const ids = dbConnection.getRepository(Identifier);
        const other =  await ids.createQueryBuilder('identifier')
            .innerJoinAndSelect("identifier.keys", "key")
            .where('did=:did', {did: request.body.original})
            .orWhere('alias=:alias', {alias: request.body.alias})
            .getOne();
        if (other) {
            throw new Error("DID already in use");
        }

        const identifier = new Identifier();
        const ckey = await createNewKey(request.body.keytype ?? '');
        await setIdentifierData(identifier, request.body.did, request.body.alias, request.body.provider, request.body.path, request.body.services, ckey);
        await ids.save(identifier);

        debug("saving new key");
        await saveKey(identifier, ckey);

        return response.status(200).json(await identifierToScheme(identifier));
    }
    catch (e) {
        response.header('Content-Type', 'application/json')
        return response.status(500).json({"error": JSON.stringify(e)});
    }
}

interface DeleteIdentifierRequest {
    did:string;
}

export async function deleteIdentifier(request: Request<DeleteIdentifierRequest>, response: Response) {
    try {
        const dbConnection = getDbConnection();
        const krepo = dbConnection.getRepository(Key);
        const pkeys = dbConnection.getRepository(PrivateKey);
        const ids = dbConnection.getRepository(Identifier);

        const identifier =  await ids.createQueryBuilder('identifier')
            .innerJoinAndSelect("identifier.keys", "key")
            .where('did=:did', {did: request.body.did})
            .getOne();
        if (!identifier) {
            throw new Error("Identifier not found for POST");
        }
        
        for (const key of identifier.keys) {
            await pkeys.delete({alias:key.kid});
            await krepo.delete({kid:key.kid});
        }

        await ids.delete({did: request.body.did});
        debug("removed identifier, returning status 202");
        return response.status(202).json([]);
    }
    catch (e) {
        debug("Caught error on deleting identifier ", e);
        response.header('Content-Type', 'application/json')
        return response.status(500).json({"error": JSON.stringify(e)});
    }
}

async function createNewKey(keytype:string)
{
    const ckey = await Factory.createFromType(keytype);
    await ckey.createPrivateKey();
    return ckey;
}

async function saveKey(id:Identifier, ckey:CryptoKey)
{
    const dbConnection = getDbConnection();
    const dbKey = new Key();
    dbKey.kid = ckey.exportPublicKey();
    dbKey.kms = 'local';
    dbKey.type = ckey.keyType;
    dbKey.publicKeyHex = dbKey.kid;
    dbKey.identifier = id;
    const krepo = dbConnection.getRepository(Key);
    await krepo.save(dbKey);
    
    const pKey = new PrivateKey();
    pKey.alias = dbKey.kid;
    pKey.type = dbKey.type;
    pKey.privateKeyHex = ckey.exportPrivateKey();
    const prepo = dbConnection.getRepository(PrivateKey);
    await prepo.save(pKey);
}

