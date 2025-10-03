import { Key } from './entities/Key.js'
import { Identifier } from './entities/Identifier.js'
import { PrivateKey } from './entities/PrivateKey.js'
import { Presentation } from './entities/Presentation.js';

export const Entities = [
  Key,
  Identifier,
  PrivateKey,
  Presentation
]

export {
  Key,
  Identifier,
  PrivateKey,
}
export { migrations } from './migrations/index.js'
