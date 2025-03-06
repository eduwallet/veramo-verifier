import { contextFromKeyFormat, CryptoKey, SupportedVerificationMethods } from "./CryptoKey";
import { randomBytes } from 'node:crypto';
import { SigningKey } from 'ethers';
import { ES256Signer } from 'did-jwt'
import { multibaseToBytes, createJWK } from '@veramo/utils';
import { VerificationMethod } from "did-resolver";
import elliptic from 'elliptic'

export class Secp256r1 extends CryptoKey {
    constructor () {
        super();
        this.keyType = 'Secp256r1';
        this.codecCode = 0x1200;
    }

    createPrivateKey() {
        const key = new elliptic.ec('p256');
        const keypair = key.genKeyPair();
        this.initialisePrivateKey(this.hexToBytes(keypair.getPrivate('hex')));
    }

    initialisePrivateKey(key: any): void {
        const p256key = new elliptic.ec('p256');
        const keypair = p256key.keyFromPrivate(key);
        this.privateKeyBytes = key;
        this.publicKeyBytes = this.hexToBytes(keypair.getPublic(true, 'hex'));
    }

    importFromDid(didKey: string): void {
        if (!didKey.startsWith('did:key:zDn')) {
            throw new Error('Secp256r1 did:key must start with did:key:zDn prefix');
        }
        const keyMultibase = didKey.substring(8);
        const result = multibaseToBytes(keyMultibase);
        const resultKeyType:string|undefined = result.keyType?.toString();
        if (!resultKeyType || (resultKeyType !== 'P-256' && resultKeyType !== 'Secp256r1')) {
            throw new Error(`invalidDid: the key type cannot be deduced for ${didKey}`)
        }
        this.publicKeyBytes = result.keyBytes;
    }

    didDocument(method?:SupportedVerificationMethods) {      
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
            case SupportedVerificationMethods.EcdsaSecp256r1VerificationKey2019:
                verificationMethod.publicKeyJwk = createJWK('Secp256r1', this.publicKey(), 'sig')
                break
            case SupportedVerificationMethods.Multikey:
            case SupportedVerificationMethods.EcdsaSecp256k1VerificationKey2019:
            case SupportedVerificationMethods.EcdsaSecp256k1VerificationKey2020:
                verificationMethod.publicKeyMultibase = keyMultibase
                break
            default:
                throw new Error(`invalidPublicKeyType: Unsupported public key format ${publicKeyFormat}`)
        }

        let ldContext = {}
        const acceptedFormat:string = 'application/did+ld+json'
        if (acceptedFormat === 'application/did+json') {
            ldContext = {}
        }
        else if (acceptedFormat === 'application/did+ld+json') {
          ldContext = { '@context': ['https://www.w3.org/ns/did/v1', contextFromKeyFormat[publicKeyFormat]]}
        }
        else {
          throw new Error(
            `unsupportedFormat: The DID resolver does not support the requested 'accept' format: ${acceptedFormat}`,
          )
        }
      
        return {
          didResolutionMetadata: {},
          didDocumentMetadata: { contentType: 'application/did+ld+json' },
          didDocument: {
            ...ldContext,
            id: did,
            verificationMethod: [verificationMethod],
            authentication: [verificationMethod.id],
            assertionMethod: [verificationMethod.id],
            capabilityDelegation: [verificationMethod.id],
            capabilityInvocation: [verificationMethod.id],
          },
        }
    }
    
    algorithms() {
        return ['ES256'];
    }

    async sign(algorithm:string, data:Uint8Array)
    {
        if (!this.algorithms().includes(algorithm)) {
            throw new Error("Algorithm " + algorithm + ' not supported on key type ' + this.keyType);
        }
        const signer = ES256Signer(this.privateKeyBytes);
        const signature = await signer(data);
        // base64url encoded string
        return signature as string        
    }
}