import {
  DIDResolutionResult,
  DIDResolver,
  ParsedDID,
  Resolvable,
} from 'did-resolver'
import { Factory } from '../../crypto/Factory'

enum SupportedVerificationMethods {
  'JsonWebKey2020',
  'Multikey',
  'EcdsaSecp256k1VerificationKey2019', // deprecated,
  'EcdsaSecp256k1VerificationKey2020',
  'Ed25519VerificationKey2020',
  'Ed25519VerificationKey2018', // deprecated,
  'X25519KeyAgreementKey2020',
  'X25519KeyAgreementKey2019', // deprecated,
  'EcdsaSecp256r1VerificationKey2019',
}

const resolveDidKey: DIDResolver = async (
  didUrl: string,
  _parsed: ParsedDID,
  _resolver: Resolvable,
  options: any,
): Promise<DIDResolutionResult> => {
  try {
    const cryptoKey = await Factory.createFromDidKey(didUrl);
    return {
        didDocumentMetadata: {},
        didResolutionMetadata: {},
        ...cryptoKey.didDocument(),
    }
  }
  catch (err: any) {
    return {
      didDocumentMetadata: {},
      didResolutionMetadata: { error: 'invalidDid', message: err.toString() },
      didDocument: null,
    }
  }
}

/**
 * Provides a mapping to a did:key resolver, usable by {@link did-resolver#Resolver}.
 *
 * @public
 */
export function getDidKeyResolver() {
  return { key: resolveDidKey }
}
