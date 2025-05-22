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

// Core identity manager plugin
import { DIDManager } from '@veramo/did-manager'
     
import { KeyManager } from './packages/keymanager/key-manager';
import { KeyManagementSystem } from './packages/kms/key-management-system'
  
// W3C Verifiable Credential plugin
import { CredentialPlugin } from '@veramo/credential-w3c'

// W3C JSON-LD Verifiable Credentials 
import { CredentialIssuerLD } from '@veramo/credential-ld'
  
import { DIDResolverPlugin } from '@veramo/did-resolver'
  
// Storage plugin using TypeOrm
import { KeyStore, DIDStore, PrivateKeyStore } from './packages/datastore'
  
import { getDbConnection } from './database';
import { createDidResolver } from './utils/didResolver';
import { createDidProvider } from './utils/didProvider';

const dbConnection = await getDbConnection();
export const resolver = createDidResolver();
const providers = createDidProvider();

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
      providers: providers
    }),
    new DIDResolverPlugin({
      resolver: resolver,
    }),
    new CredentialPlugin(),
    new CredentialIssuerLD({contextMaps:[], suites:[]})
  ],
})
