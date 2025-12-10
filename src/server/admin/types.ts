import { getDbConnection } from "#root/database";
import { Identifier, Key, Presentation } from "#root/packages/datastore/index";
import moment from "moment";
import { Verifier } from "packages/datastore/entities/Verifier";

export interface DataList {
    offset: number;
    count: number;
    pagesize: number;
    data: any[];
}

export interface KeyScheme
{
    kid:string;
    type: string;
    publicKey: string;
    isController: boolean;
}


export interface IdentifierScheme
{
    did: string;
    provider: string;
    alias: string;
    path?:string;
    services?:string;
    saved: string;
    updated:string;
    keys:KeyScheme[];
}

export async function identifierToScheme(id:Identifier) {
    const retval:IdentifierScheme = {
        did: id.did,
        provider: id.provider || '',
        alias: id.alias || '',
        ...(id.path && {path: id.path}),
        ...(id.services && {services: id.services}),
        saved: moment(id.saveDate).format('YYYY-MM-DD HH:mm:ss'),
        updated: moment(id.updateDate).format('YYYY-MM-DD HH:mm:ss'),
        keys: []
    };

    const dbConnection = await getDbConnection();
    const keys = dbConnection.getRepository(Key);
    id.keys = await keys.createQueryBuilder('key').relation(Identifier, "keys").of(id).loadMany();

    for(const key of id.keys) {
        retval.keys.push({
            kid: key.kid,
            type: key.type,
            publicKey: key.publicKeyHex,
            isController: key.kid === id.controllerKeyId
        });
    }
    return retval;
}

export interface PresentationScheme
{
    id:number;
    shortname:string;
    name:string;
    purpose:string;
    input_descriptors?:string;
    query?:string;
    saved: string;
    updated:string;
}

export async function presentationToScheme(data:Presentation)
{
    const retval:PresentationScheme = {
        id: data.id,
        shortname: data.shortname,
        name: data.name,
        purpose: data.path,
        input_descriptors: data.input_descriptors,
        query: data.query,
        saved: moment(data.saveDate).format('YYYY-MM-DD HH:mm:ss'),
        updated: moment(data.updateDate).format('YYYY-MM-DD HH:mm:ss')
    };
    return retval;
}


export interface VerifierScheme
{
    id:number;
    name:string;
    path:string;
    did:string;
    admin_token:string;
    presentations:string;
    saved: string;
    updated:string;
}

export async function verifierToScheme(data:Verifier)
{
    const retval:VerifierScheme = {
        id: data.id,
        path: data.path,
        name: data.name,
        did: data.did,
        presentations: data.presentations ?? '[]',
        admin_token: data.admin_token,
        saved: moment(data.saveDate).format('YYYY-MM-DD HH:mm:ss'),
        updated: moment(data.updateDate).format('YYYY-MM-DD HH:mm:ss')
    };
    return retval;
}