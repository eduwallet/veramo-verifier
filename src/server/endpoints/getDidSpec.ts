import { Factory } from '@muisit/cryptokey';
import Debug from 'debug';
import { DIDStoreValue } from 'dids/Store';
import { Request, Router } from 'express'
import { sendErrorResponse } from 'server/sendErrorResponse';
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
        try {
            const didDoc = await verifier.getDidDoc();
            return res.json(didDoc);
        }
        catch (e) {
            return sendErrorResponse(res, 500, 'Invalid DID', e);
        }
    });
}

export function getDidWebSpec(router:Router, value:DIDStoreValue) {
    router!.get(value.identifier.path!, async (req: Request, res) => {
         // Sphereon requires the deprecated JsonWebKey2020 verification-method instead of the default JsonWebKey
         try {
            const didDoc = await Factory.toDIDDocument(value.key, value.identifier.did, value.identifier.services ? JSON.parse(value.identifier.services) : null, 'JsonWebKey2020');
            return res.json(didDoc);
         }
         catch (e) {
            return sendErrorResponse(res, 500, 'Invalid DID', e);
         }
    });
}
