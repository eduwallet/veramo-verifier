import Debug from 'debug';
const debug = Debug("verifier:presentations");

import { loadJsonFiles } from "@utils/loadJsonFiles";
import { resolveConfPath } from "@utils/resolveConfPath";
import { getDbConnection } from "database";
import { Presentation } from "packages/datastore/entities/Presentation";

export interface ClaimPresentation {
    id?:string;
    path: string[];
}

export interface CredentialPresentation {
    id: string;
    format: string;
    multiple?:boolean;
    require_cryptographic_holder_binding?: boolean;
    meta: any;
    claims: ClaimPresentation[];
}

export interface CredentialSet {
    options: string[];
    required?:boolean;
}

export interface PresentationQuery {
    credentials: CredentialPresentation[];
    credential_sets: CredentialSet[];
}

export interface PresentationDefinition {
    id: string;
    name: string;
    purpose: string;
    query?: any;
    input_descriptors?:any;
}

interface StoreType {
    [x:string]: PresentationDefinition;
}

var _store:StoreType = {};

export function getPresentationStore() {
    return _store;
}

export async function initialisePresentationStore() {

    try {
        const dbConnection = await getDbConnection();
        const repo = dbConnection.getRepository(Presentation);
        const objs = await repo.createQueryBuilder('presentation').getMany();
        for (const obj of objs) {
            const cfg:PresentationDefinition = {
                id: obj.shortname,
                name: obj.name,
                purpose: obj.purpose,
                input_descriptors: obj.input_descriptors,
                query: obj.query
            }
            try {
                if (cfg.input_descriptors) {
                    cfg.input_descriptors = JSON.parse(cfg.input_descriptors);
                }
            }
            catch (e) {
                cfg.input_descriptors = null;
            }
            try {
                if (cfg.query) {
                    cfg.query = JSON.parse(cfg.query);
                }
            }
            catch (e) {
                cfg.query = null;
            }
            if (cfg.input_descriptors || cfg.query) {
                _store[obj.shortname] = cfg;
            }
        } 
    
        try {
            const options = loadJsonFiles<PresentationDefinition>({path: resolveConfPath('presentations')});
            for (const opt of options.asArray) {
                if (!Object.keys(_store).includes(opt.id)) {
                    _store[opt.id] = opt;

                    const obj = new Presentation();
                    obj.shortname = opt.id;
                    obj.name = opt.name;
                    obj.purpose = opt.purpose;
                    if (opt.input_descriptors) {
                        obj.input_descriptors = JSON.stringify(opt.input_descriptors);
                    }
                    if (opt.query) {
                        obj.query  = JSON.stringify(opt.query);
                    }
                    await repo.save(obj);
                }
            }
        }
        catch (e) {
            debug("Missing presentation conf path");
        }
    }
    catch (e) {
        console.error("Caught exception on presentation initialisation", e);
    }   
}
