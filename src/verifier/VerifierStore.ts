import Debug from 'debug';
const debug = Debug('verifier:verifiers');

import { loadJsonFiles } from "@utils/loadJsonFiles";
import { resolveConfPath } from '@utils/resolveConfPath';
import { VerifierOptions, Verifier } from './Verifier';
import { getDbConnection } from "#root/database/index";
import { Verifier as VerifierEntity } from "#root/database/entities/index";
import { hasAdminBearerToken } from '@utils/adminBearerToken';

interface VerifierStoreType {
    [x:string]: Verifier;
}
var VerifierStore:VerifierStoreType = {};

export function getVerifierStore() {
    return VerifierStore;
}

async function readFromDB()
{
    try {
        const dbConnection = getDbConnection();
        const repo = dbConnection.getRepository(VerifierEntity);
        const objs = await repo.createQueryBuilder('verifier').getMany();
        for (const obj of objs) {
            const cfg:VerifierOptions = {
                name: obj.name,
                path: obj.path,
                did: obj.did,
                adminToken: obj.admin_token,
                presentations: JSON.parse(obj.presentations)
            }
            const verifier = new Verifier(cfg);
            await verifier.initialise();
            VerifierStore[verifier.name] = verifier;
        } 
    } catch (e) {
        console.error("Caught exception on verifier initialisation", e);
    }
}

async function clearDB()
{
    try {
        const dbConnection = getDbConnection();
        const repo = dbConnection.getRepository(VerifierEntity);
        await repo.clear();
    } catch (e) {
        console.error("Caught exception on verifier initialisation", e);
    }
}

async function readFromFile()
{
    try {
        const dbConnection = getDbConnection();
        const repo = dbConnection.getRepository(VerifierEntity);

        try {
            const options = loadJsonFiles<VerifierOptions>({path: resolveConfPath('verifiers')});
            for (const opt of options.asArray) {
                if (!Object.keys(VerifierStore).includes(opt.name)) {
                    const verifier = new Verifier(opt);
                    await verifier.initialise();
                    VerifierStore[verifier.name] = verifier;

                    const obj = new VerifierEntity();
                    obj.path = opt.path;
                    obj.name = opt.name;
                    obj.did = opt.did;
                    obj.admin_token = opt.adminToken;
                    obj.presentations = JSON.stringify(opt.presentations);
                    await repo.save(obj);
                }
            }
        }
        catch (e) {
            debug("Missing conf path for verifiers");
        }
    } catch (e) {
        console.error("Caught exception on verifier initialisation", e);
    }
}

export async function createVerifiers() {
    if (hasAdminBearerToken()) {
        await readFromDB();
    }
    else {
        await clearDB();
    }
    await readFromFile();
}