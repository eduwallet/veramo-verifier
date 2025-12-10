import { Key } from './entities/Key.js'
import { Identifier } from './entities/Identifier.js'
import { PrivateKey } from './entities/PrivateKey.js'
import { Presentation } from './entities/Presentation.js';
import { Verifier } from './entities/Verifier.js';
import { Session } from './entities/Session.js';

export const Entities = [
  Key,
  Identifier,
  PrivateKey,
  Presentation,
  Verifier,
  Session
]

export {
  Key,
  Identifier,
  PrivateKey,
  Presentation,
  Verifier,
  Session
}
export { migrations } from './migrations/index.js'
