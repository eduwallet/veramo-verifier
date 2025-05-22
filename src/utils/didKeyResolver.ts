import Debug from 'debug';
const debug = Debug('issuer:didkey');
import { DIDResolutionOptions, DIDResolutionResult, ParsedDID, Resolvable } from 'did-resolver'
import { Factory } from '@muisit/cryptokey';

const resolveDidKey = async (
    didUrl: string,
    _parsed: ParsedDID,
    _resolver: Resolvable,
    options: DIDResolutionOptions,
  ): Promise<DIDResolutionResult> => {

    try {
        const key = await Factory.resolve(didUrl);
        if (key) {
            debug("found resolution using cryptokey");
            return {
                didDocumentMetadata: {},
                didResolutionMetadata: {},
                didDocument: await Factory.toDIDDocument(key)
            };
        }
    }
    catch (err: any) {
        debug('agent did:key: ', err);
    }

    debug("returning key method not supported");
    return {
        didDocumentMetadata: {},
        didResolutionMetadata: { error: 'invalidDid', message: 'key method not supported' },
        didDocument: null,
    }
}

export function getDidKeyResolver() {
    return { key: resolveDidKey }
}
  