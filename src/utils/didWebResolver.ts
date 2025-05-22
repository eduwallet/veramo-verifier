import Debug from 'debug';
const debug = Debug('issuer:didweb');
import { DIDResolutionOptions, DIDResolutionResult, ParsedDID, Resolvable } from 'did-resolver'
import { Factory } from '@muisit/cryptokey';

const resolveDidWeb = async (
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
    catch (err: any) {}

    return {
        didDocumentMetadata: {},
        didResolutionMetadata: { error: 'invalidDid', message: 'key method not supported' },
        didDocument: null,
    }
}

export function getDidWebResolver() {
    return { web: resolveDidWeb }
}
  