import { contextFromKeyFormat, CryptoKey, SupportedVerificationMethods } from "./CryptoKey";
import { x25519 } from '@noble/curves/ed25519'
import { multibaseToBytes, bytesToBase58, createJWK, convertEd25519PublicKeyToX25519} from '@veramo/utils';
import { VerificationMethod } from "did-resolver";

export class X25519 extends CryptoKey {
    constructor () {
        super();
        this.keyType = 'X25519';
        this.codecCode = 0xec;

    }

    createPrivateKey() {
        this.privateKeyBytes = x25519.utils.randomPrivateKey();
        this.publicKeyBytes = x25519.getPublicKey(this.privateKeyBytes);
    }

    importFromDid(didKey: string): void {
        if(!didKey.startsWith('did:key:z6LS')) {
            throw new Error("X25519 did:key must start with did:key:z6LS prefix");
        }
        const keyMultibase = didKey.substring(8)
        const result = multibaseToBytes(keyMultibase);
        if (!result.keyType || result.keyType !== 'X25519') {
            throw new Error(`invalidDid: the key type cannot be deduced for ${didKey}`)
        }
        this.publicKeyBytes = result.keyBytes;
    }

    didDocument(method?:SupportedVerificationMethods)
    {
        const publicKeyFormat:SupportedVerificationMethods = method || SupportedVerificationMethods.JsonWebKey2020;
      
        const keyMultibase = this.makeDidKeyIdentifier();
        const did = 'did:key:' + keyMultibase;
        let verificationMethod: VerificationMethod = {
          id: `${did}#${keyMultibase}`,
          type: publicKeyFormat.toString(),
          controller: did,
        }
      
        switch (publicKeyFormat) {
          case SupportedVerificationMethods.JsonWebKey2020:
            verificationMethod.publicKeyJwk = createJWK(this.keyType as any, this.publicKey(), 'enc')
            break
          case SupportedVerificationMethods.Multikey:
          case SupportedVerificationMethods.X25519KeyAgreementKey2020:
            verificationMethod.publicKeyMultibase = keyMultibase
            break
          case SupportedVerificationMethods.X25519KeyAgreementKey2019:
            verificationMethod.publicKeyBase58 = bytesToBase58(this.publicKey());
            break
          default:
            throw new Error(`invalidPublicKeyType: Unsupported public key format ${publicKeyFormat}`)
        }
        const ldContextArray = ['https://www.w3.org/ns/did/v1', contextFromKeyFormat[publicKeyFormat]]
      
        const result = {
          didResolutionMetadata: {},
          didDocumentMetadata: { contentType: 'application/did+ld+json' },
          didDocument: {
            id: did,
            verificationMethod: [verificationMethod],
            keyAgreement: [verificationMethod.id],
          },
        }
      
        let ldContext = {}
        const acceptedFormat:string = 'application/did+ld+json'
        if (acceptedFormat === 'application/did+json') {
          ldContext = {}
        } else if (acceptedFormat === 'application/did+ld+json') {
          ldContext = {
            '@context': ldContextArray,
          }
        } else {
          throw new Error(
            `unsupportedFormat: The DID resolver does not support the requested 'accept' format: ${acceptedFormat}`,
          )
        }
      
        result.didDocument = { ...result.didDocument, ...ldContext }
        return result        
    }

    algorithms() {
        return ['ECDH', 'ECDH-ES', 'ECDH-1PU'];
    }
}