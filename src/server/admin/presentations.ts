import Debug from 'debug';
const debug = Debug('server:api');

import { getDbConnection } from '#root/database';
import { Presentation} from "#root/packages/datastore/index";
import { Request, Response } from 'express'
import { DataList, presentationToScheme } from './types.js';

export async function listPresentations(request: Request, response: Response) {
    try {
        const data:DataList = {
            offset: 0,
            count: 0,
            pagesize: 50,
            data: []
        };
        const dbConnection = await getDbConnection();
        const repo = dbConnection.getRepository(Presentation);
        const objs =  await repo.createQueryBuilder('presentation').orderBy("presentation.name").getMany();
        data.count = objs.length;
        for (const obj of objs) {
            data.data.push(await presentationToScheme(obj));
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
    shortname:string;
    name:string;
    purpose:string;
    input_descriptors:string;
    query:string;
}

async function setData(obj:Presentation, shortname:string, name:string, purpose:string, input_descriptors:string, query:string)
{
    obj.shortname = shortname;
    obj.name = name;
    obj.purpose = purpose;
    if (input_descriptors !== '' && input_descriptors.length) {
        obj.input_descriptors = input_descriptors;
    }
    else {
        obj.input_descriptors = null;
    }
    if (query && query !== '' && query.length) {
        obj.query = query;
    }
    else {
        obj.query = null;
    }
}

export async function storePresentation(request: Request<StoreRequest>, response: Response) {
    try {
        const dbConnection = await getDbConnection();
        const repo = dbConnection.getRepository(Presentation);
        const obj =  await repo.createQueryBuilder('presentation')
            .where('id=:id', {id: request.body.id})
            .getOne();
        if (!obj) {
            throw new Error("Presentation not found for POST");
        }

        await setData(obj, request.body.shortname, request.body.name, request.body.purpose, request.body.input_descriptors ?? '', request.body.query ?? '');
        await repo.save(obj);

        return response.status(200).json(await presentationToScheme(obj));
    }
    catch (e) {
        debug("storePresentation: caught", e);
        response.header('Content-Type', 'application/json')
        return response.status(500).json({"error": JSON.stringify(e)});
    }
}

interface CreateRequest {
    shortname:string;
    name:string;
    purpose:string;
    input_descriptors:string;
    query:string;
}
export async function createPresentation(request: Request<CreateRequest>, response: Response) {
    try {
        const dbConnection = await getDbConnection();
        const repo = dbConnection.getRepository(Presentation);
        const other =  await repo.createQueryBuilder('presentation')
            .where('shortname=:name', {name: request.body.shortname})
            .getOne();
        if (other) {
            throw new Error("Presentation type name already in use");
        }

        const obj = new Presentation();
        await setData(obj, request.body.shortname, request.body.name, request.body.purpose, request.body.input_descriptors ?? '', request.body.query ?? '');
        await repo.save(obj);

        const json = await presentationToScheme(obj);
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

export async function deletePresentation(request: Request<DeleteRequest>, response: Response) {
    try {
        const dbConnection = await getDbConnection();
        const repo = dbConnection.getRepository(Presentation);

        const obj =  await repo.createQueryBuilder('presentation')
            .where('id=:id', {id: request.body.id})
            .getOne();
        if (!obj) {
            throw new Error("Presentation not found for DELETE");
        }
        
        await repo.delete({id: request.body.id});
        return response.status(202).json([]);
    }
    catch (e) {
        debug("Caught error on deleting presentation ", e);
        response.header('Content-Type', 'application/json')
        return response.status(500).json({"error": JSON.stringify(e)});
    }
}
