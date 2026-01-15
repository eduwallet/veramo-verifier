import Debug from 'debug';
const debug = Debug('server:api');

import { getDbConnection } from '#root/database';
import { Verifier } from "#root/packages/datastore/index";
import { Request, Response } from 'express'
import { DataList, verifierToScheme } from './types.js';

export async function listVerifiers(request: Request, response: Response) {
    try {
        const data:DataList = {
            offset: 0,
            count: 0,
            pagesize: 50,
            data: []
        };
        const dbConnection = await getDbConnection();
        const repo = dbConnection.getRepository(Verifier);
        const objs =  await repo.createQueryBuilder('verifier').orderBy("verifier.name").getMany();
        data.count = objs.length;
        for (const obj of objs) {
            data.data.push(await verifierToScheme(obj));
        }

        return response.status(200).json(data);
    }
    catch (e) {
        response.header('Content-Type', 'application/json')
        return response.status(500).json({"error": JSON.stringify(e)});
    }
}

interface StoreRequest {
    id:number;
    path:string;
    name:string;
    did:string;
    admin_token:string;
    metadata?:string;
    presentations:any;
}

async function setData(obj:Verifier, name:string, path:string, did:string, admin_token:string, presentations:string, metadata?:string)
{
    obj.path = path;
    obj.name = name;
    obj.did = did;
    obj.admin_token = admin_token;
    obj.metadata = metadata;
    const presString = JSON.stringify(presentations);
    if (presString && presString.length) {
        obj.presentations = presString;
    }
    else {
        obj.presentations = '[]';
    }
}

export async function storeVerifier(request: Request<StoreRequest>, response: Response) {
    try {
        const dbConnection = await getDbConnection();
        const repo = dbConnection.getRepository(Verifier);
        const obj =  await repo.createQueryBuilder('verifier')
            .where('id=:id', {id: request.body.id})
            .getOne();
        if (!obj) {
            throw new Error("Verifier not found for POST");
        }

        await setData(obj, request.body.name, request.body.path, request.body.did, request.body.admin_token, request.body.presentations, request.body.metadata);
        await repo.save(obj);

        return response.status(200).json(await verifierToScheme(obj));
    }
    catch (e) {
        debug("storePresentation: caught", e);
        response.header('Content-Type', 'application/json')
        return response.status(500).json({"error": JSON.stringify(e)});
    }
}

interface CreateRequest {
    name:string;
    path:string;
    did:string;
    admin_token:string;
    metadata?:string;
    presentations:any;
}
export async function createVerifier(request: Request<CreateRequest>, response: Response) {
    try {
        const dbConnection = await getDbConnection();
        const repo = dbConnection.getRepository(Verifier);
        const other =  await repo.createQueryBuilder('verifier')
            .where('path=:path', {path: request.body.path})
            .getOne();
        if (other) {
            throw new Error("Verifier path already in use");
        }

        const obj = new Verifier();
        await setData(obj, request.body.name, request.body.path, request.body.did, request.body.admin_token, request.body.presentations, request.body.metadata);
        await repo.save(obj);

        const json = await verifierToScheme(obj);
        return response.status(200).json(json);
    }
    catch (e) {
        response.header('Content-Type', 'application/json')
        return response.status(500).json({"error": JSON.stringify(e)});
    }
}

interface DeleteRequest {
    id:number;
}

export async function deleteVerifier(request: Request<DeleteRequest>, response: Response) {
    try {
        const dbConnection = await getDbConnection();
        const repo = dbConnection.getRepository(Verifier);

        const obj =  await repo.createQueryBuilder('verifier')
            .where('id=:id', {id: request.body.id})
            .getOne();
        if (!obj) {
            throw new Error("Verifier not found for DELETE");
        }
        
        await repo.delete({id: request.body.id});
        return response.status(202).json([]);
    }
    catch (e) {
        debug("Caught error on deleting verifier ", e);
        response.header('Content-Type', 'application/json')
        return response.status(500).json({"error": JSON.stringify(e)});
    }
}
