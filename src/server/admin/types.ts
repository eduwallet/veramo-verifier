import { getDbConnection } from "#root/database";
import { Identifier, Key } from "#root/packages/datastore/index";
import moment from "moment";

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
    saved: string;
    updated:string;
    keys:KeyScheme[];
}

export async function identifierToScheme(id:Identifier) {
    const retval:IdentifierScheme = {
        did: id.did,
        provider: id.provider || '',
        alias: id.alias || '',
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
