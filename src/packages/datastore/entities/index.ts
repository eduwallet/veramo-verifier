import { Key } from './Key'
import { Identifier } from './Identifier'
import { PrivateKey } from './PrivateKey'

/**
 * The TypeORM entities used by this package.
 *
 * This array SHOULD be used when creating a TypeORM connection.
 *
 * @public
 */
export const Entities = [
  Key,
  Identifier,
  PrivateKey
]