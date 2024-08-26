import { loadJsonFiles } from "@utils/loadJsonFiles";
import { resolveConfPath } from '@utils/resolveConfPath';
import { VerifierOptions, Verifier } from './Verifier';

interface VerifierStoreType {
    [x:string]: Verifier;
}
var VerifierStore:VerifierStoreType = {};

export function getVerifierStore() {
    return VerifierStore;
}

export async function createVerifiers() {
    const options = loadJsonFiles<VerifierOptions>({path: resolveConfPath('verifiers')});
    for (const opt of options.asArray) {
        const verifier = new Verifier(opt);
        await verifier.initialise();
        VerifierStore[verifier.name] = verifier;
    }
}