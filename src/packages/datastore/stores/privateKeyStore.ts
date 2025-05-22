import {
  AbstractPrivateKeyStore,
  ImportablePrivateKey,
  ManagedPrivateKey,
} from '@veramo/key-manager'
import { PrivateKey } from '../entities/PrivateKey'
import { v4 as uuid4 } from 'uuid'
import Debug from 'debug'
import { getDbConnection } from '../../../database';

const debug = Debug('issuer:stores')

/**
 * An implementation of {@link @veramo/key-manager#AbstractPrivateKeyStore | AbstractPrivateKeyStore} that uses a
 * TypeORM database connection to store private key material.
 * @public
 */
export class PrivateKeyStore extends AbstractPrivateKeyStore {
  constructor(private dbConnection: any) {
    super()
  }

  async getKey({ alias }: { alias: string }): Promise<ManagedPrivateKey> {
    const key = await (await getDbConnection()).getRepository(PrivateKey).findOneBy({ alias })
    if (!key) throw Error('Key not found')
    return key as ManagedPrivateKey
  }

  async deleteKey({ alias }: { alias: string }) {
    const key = await (await getDbConnection()).getRepository(PrivateKey).findOneBy({ alias })
    if (!key) throw Error(`not_found: Private Key data not found for alias=${alias}`)
    debug('Deleting private key data', alias)
    await (await getDbConnection()).getRepository(PrivateKey).remove(key)
    return true
  }

  async importKey(args: ImportablePrivateKey): Promise<ManagedPrivateKey> {
    const key = new PrivateKey()
    key.alias = args.alias || uuid4()
    key.privateKeyHex = args.privateKeyHex
    key.type = args.type
    debug('Saving private key data', args.alias)
    const keyRepo = await (await getDbConnection()).getRepository(PrivateKey)
    const existingKey = await keyRepo.findOneBy({ alias: key.alias })
    if (existingKey && existingKey.privateKeyHex !== key.privateKeyHex) {
      throw new Error(
        `key_already_exists: A key with this alias exists but with different data. Please use a different alias.`,
      )
    }
    await keyRepo.save(key)
    return key as ManagedPrivateKey;
  }

  async listKeys(): Promise<Array<ManagedPrivateKey>> {
    let keys = await (await getDbConnection()).getRepository(PrivateKey).find()
    return keys as ManagedPrivateKey[];
  }
}
