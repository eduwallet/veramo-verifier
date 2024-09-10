// Core interfaces
import {
    createAgent,
    IDIDManager,
    IResolver,
    IDataStore,
    IDataStoreORM,
    IKeyManager,
    ICredentialPlugin,
} from '@veramo/core'
import { getEnv } from 'utils/getEnv';

// Core identity manager plugin
import { DIDManager } from '@veramo/did-manager'
  
import { WebDIDProvider } from "@veramo/did-provider-web";
import { JwkDIDProvider, getDidJwkResolver } from "@veramo/did-provider-jwk";
import { KeyDIDProvider } from "@veramo/did-provider-key";
import { getResolver as getDidKeyResolver } from '@sphereon/ssi-sdk-ext.did-resolver-key';
import { IonDIDProvider, getDidIonResolver } from "@veramo/did-provider-ion";
    
// Core key manager plugin
import { KeyManager } from '@veramo/key-manager'
  
// Custom key management system for RN
import { KeyManagementSystem, SecretBox } from '@veramo/kms-local'
  
// W3C Verifiable Credential plugin
import { CredentialPlugin } from '@veramo/credential-w3c'

// W3C JSON-LD Verifiable Credentials 
import { CredentialIssuerLD } from '@veramo/credential-ld'
  
// Custom resolvers
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { Resolver } from 'did-resolver'
import { getResolver as webDidResolver } from 'web-did-resolver'
  
// Storage plugin using TypeOrm
import { KeyStore, DIDStore, PrivateKeyStore } from '@veramo/data-store'
  
// This will be the secret key for the KMS (replace this with your secret key)
// run  npx @veramo/cli config create-secret-key
const KMS_SECRET_KEY = getEnv('DB_ENCRYPTION_KEY', 'secretkey');
import { getDbConnection } from './database';
const dbConnection = await getDbConnection();
const webprov = new WebDIDProvider({defaultKms: 'local' });
const jwkprov = new JwkDIDProvider({defaultKms: 'local' });
const keyprov = new KeyDIDProvider({defaultKms: 'local' });
const ionprov = new IonDIDProvider({defaultKms: 'local' });

export const resolver = new Resolver({
  ...webDidResolver(),
  ...getDidIonResolver(),
  ...getDidJwkResolver(),
  ...getDidKeyResolver()
});

export const agent = createAgent<
IDIDManager & IKeyManager & IDataStore & IDataStoreORM & IResolver & ICredentialPlugin
>({
  plugins: [
    new KeyManager({
      store: new KeyStore(dbConnection),
      kms: {
//        local: new KeyManagementSystem(new PrivateKeyStore(dbConnection, new SecretBox(KMS_SECRET_KEY))),
        local: new KeyManagementSystem(new PrivateKeyStore(dbConnection)),
      },
    }),
    new DIDManager({
      store: new DIDStore(dbConnection),
      defaultProvider: 'did:jwk',
      providers: {
        'did:web': webprov,
        'did:jwk': jwkprov,
        'did:key': keyprov,
        'did:ion': ionprov
      }
    }),
    new DIDResolverPlugin({
      resolver: resolver,
    }),
    new CredentialPlugin(),
    new CredentialIssuerLD({contextMaps:[], suites:[]})
  ],
})
