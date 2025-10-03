import { loadJsonFiles } from "@utils/loadJsonFiles";
import { resolveConfPath } from '@utils/resolveConfPath';
import { VerifierOptions, Verifier } from './Verifier';
import { getDbConnection } from "database";
import { Verifier as VerifierEntity } from "packages/datastore/entities/Verifier";

interface VerifierStoreType {
    [x:string]: Verifier;
}
var VerifierStore:VerifierStoreType = {};

export function getVerifierStore() {
    return VerifierStore;
}

export async function createVerifiers() {
    const dbConnection = await getDbConnection();
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