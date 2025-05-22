// base largely on the veramo/data-store plugin

export { DIDStore } from './stores/didStore'
export { KeyStore } from './stores/keyStore'
export { PrivateKeyStore } from './stores/privateKeyStore'
export { DataStoreORM } from './dataStoreORM'
import { Key } from './entities/Key'
import { Identifier } from './entities/Identifier'
import { PrivateKey } from './entities/PrivateKey'

/**
 * The TypeORM entities used by this package.
 *
 * This array SHOULD be used when creating a TypeORM connection.
 *
 * @public
 */
export { Entities } from './entities/index';

export {
  Key,
  Identifier,
  PrivateKey
}
export { migrations } from './migrations/index'
