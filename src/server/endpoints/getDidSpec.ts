import Debug from 'debug';
import { Request } from 'express'
import { Verifier } from 'verifier/Verifier';

const debug = Debug('server:didspec');

export function getDidSpec(verifier:Verifier) {
    var path = '/.well-known/did.json';
    var idparts = verifier.did.split(':');
    if (idparts.length > 3) {
        // the did contains a subpath.
        // This is a setup we use in development, where we want to retrieve the did directly from the agent
        // by using a subpath in the did specification. It may be usable in production environments, if we
        // have specific verifiers at subpaths. However, it is more likely all these verifiers use the same
        // did from the main domain
        path = '/did.json';
    }
    verifier.router!.get(path, async (req: Request, res) => {
        debug("getting did.json for", verifier.name);
        const didDoc = verifier.getDidDoc();
        res.json(didDoc);
    });
}
