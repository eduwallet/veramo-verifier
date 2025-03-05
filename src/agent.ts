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
import { KeyDIDProvider } from "./packages/did-key-provider";
import { getResolver as getDidKeyResolver } from '@sphereon/ssi-sdk-ext.did-resolver-key';
    
// Custom key manager plugin
import { KeyManager } from './packages/keymanager/key-manager';
  
// Custom key management system
import { KeyManagementSystem } from './packages/kms/key-management-system'
  
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
  
import { getDbConnection } from './database';
const dbConnection = await getDbConnection();
const webprov = new WebDIDProvider({defaultKms: 'local' });
const jwkprov = new JwkDIDProvider({defaultKms: 'local' });
const keyprov = new KeyDIDProvider({defaultKms: 'local' });

export const resolver = new Resolver({
  ...webDidResolver(),
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
        local: new KeyManagementSystem(new PrivateKeyStore(dbConnection)),
      },
    }),
    new DIDManager({
      store: new DIDStore(dbConnection),
      defaultProvider: 'did:jwk',
      providers: {
        'did:web': webprov,
        'did:jwk': jwkprov,
        'did:key': keyprov
      }
    }),
    new DIDResolverPlugin({
      resolver: resolver,
    }),
    new CredentialPlugin(),
    new CredentialIssuerLD({contextMaps:[], suites:[]})
  ],
})
