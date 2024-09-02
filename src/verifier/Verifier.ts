import { DIDDocument, IIdentifier, IKey, TKeyType } from "@veramo/core";
import { agent } from '../agent';
import { InMemoryRPSessionManager, PresentationVerificationResult, RP} from '@sphereon/did-auth-siop'
import { getKey } from '@sphereon/ssi-sdk-ext.did-utils'
import { createRPInstance } from './createRPInstance'
import { Router } from "express";
import { EventEmitter } from "typeorm/platform/PlatformTools";
import { Alg } from "@sphereon/oid4vci-common";
import { toJwk, JwkKeyUse } from '@sphereon/ssi-sdk-ext.key-utils';
import { getBaseUrl } from "@utils/getBaseUrl";
import { VerificationMethod } from "did-resolver";
import { getIdentifier } from "@utils/createDids";

export interface VerifierOptions {
    name:string;
    did:string;
    adminToken:string;
    path:string;
}


// mapping key types to key output types in the DIDDocument
const keyMapping: Record<TKeyType, string> = {
    Secp256k1: 'EcdsaSecp256k1VerificationKey2019',
    Secp256r1: 'EcdsaSecp256r1VerificationKey2019',
    // we need JsonWebKey2020 output
    Ed25519: 'JsonWebKey2020', //'Ed25519VerificationKey2018', 
    X25519: 'X25519KeyAgreementKey2019',
    Bls12381G1: 'Bls12381G1Key2020',
    Bls12381G2: 'Bls12381G2Key2020',
    RSA: 'RsaVerificationKey2018'
  }
  
  const algMapping: Record<TKeyType, Alg> = {
    Ed25519: Alg.EdDSA,
    X25519: Alg.EdDSA,
    Secp256r1: Alg.ES256,
    Secp256k1: Alg.ES256K,
    RSA: Alg.RS512,
    Bls12381G1: Alg.ES256, // incorrect
    Bls12381G2: Alg.ES256 // incorrect
  }
export class Verifier {
    public name:string;
    public did:string;
    public adminToken:string;
    public identifier:IIdentifier|undefined;
    public key:IKey|undefined;
    public rp:RP|undefined;
    public router:Router|undefined;
    public path:string;
    public eventEmitter:EventEmitter;
    public sessionManager:InMemoryRPSessionManager;

    public constructor(opts:VerifierOptions)
    {
        this.name = opts.name;
        this.did = opts.did;
        this.adminToken = opts.adminToken;
        this.path = opts.path;
        this.eventEmitter = new EventEmitter();
        this.sessionManager = new InMemoryRPSessionManager(this.eventEmitter);
    }

    public async initialise() {
        // allow specifying a did or a did alias in the did field
        this.identifier = await getIdentifier(this.did, this.did);
        // this must return a valid entry, unless we have a case of a bad configuration, in which case we can
        // safely throw an exception
        this.key = await getKey({identifier: this.identifier!, vmRelationship: "verificationMethod"}, {agent});
        this.rp = createRPInstance(this);
    }

    public getPresentationVerificationCallback() {
        return async (args:any):Promise<PresentationVerificationResult> => {
            return {
                verified: true
            }
        };
    }

    public signingAlgorithm():string
    {
      return algMapping[this.key!.type];
    }

    public getDidDoc ():DIDDocument {
      if (!this.identifier?.did.startsWith('did:web:')) {
          throw new Error("no DID document for non-webbased did");
      }
        const allKeys = this.identifier!.keys.map((key) => ({
          id: this.identifier!.did + '#' + key.kid,
          type: keyMapping[key.type],
          controller: this.identifier!.did,
          publicKeyJwk: toJwk(key.publicKeyHex, key.type, { use: JwkKeyUse.Signature, key: key}) as JsonWebKey,
        }));
      
        const services = this.identifier!.keys.map((key) => ({
          id: this.identifier!.did + '#' + key.kid,
          type: "OID4VCP",
          serviceEndpoint: getBaseUrl() + this.path
        }));
      
        // ed25519 keys can also be converted to x25519 for key agreement
        const keyAgreementKeyIds = allKeys
          .filter((key) => ['Ed25519VerificationKey2018', 'X25519KeyAgreementKey2019'].includes(key.type))
          .map((key) => key.id)
        const signingKeyIds = allKeys
          .filter((key) => key.type !== 'X25519KeyAgreementKey2019')
          .map((key) => key.id)
      
        const didDoc:DIDDocument = {
          '@context': 'https://w3id.org/did/v1',
          id: this.identifier!.did,
          verificationMethod: allKeys as VerificationMethod[],
          authentication: signingKeyIds,
          assertionMethod: signingKeyIds,
          keyAgreement: keyAgreementKeyIds,
          service: [...services, ...(this.identifier?.services || [])],
        }
      
        return didDoc;
      }
  }