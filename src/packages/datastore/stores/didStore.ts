import { IIdentifier, IKey } from '@veramo/core-types'
import { AbstractDIDStore } from '@veramo/did-manager'
import { Identifier } from '../entities/Identifier'
import { Key } from '../entities/Key'
import { IsNull, Not } from 'typeorm'

import Debug from 'debug'
import { getDbConnection } from '../../../database'

const debug = Debug('issuer:store')

/**
 * An implementation of {@link @veramo/did-manager#AbstractDIDStore | AbstractDIDStore} that uses a TypeORM database to
 * store the relationships between DIDs, their providers and controllers and their keys and services as they are known
 * and managed by a Veramo agent.
 *
 * An instance of this class can be used by {@link @veramo/did-manager#DIDManager} as the data storage layer.
 *
 * To make full use of this class, it should use the same database as the one used by
 * {@link @veramo/data-store#KeyStore | KeyStore}.
 *
 * @public
 */
export class DIDStore extends AbstractDIDStore {
  constructor(private dbConnection: any) {
    super()
  }

  async getDID({
    did,
    alias,
    provider,
  }: {
    did: string
    alias: string
    provider: string
  }): Promise<IIdentifier> {
    let where: { did?: string; alias?: string; provider?: string } = {}
    if (did !== undefined && alias === undefined) {
      where = { did }
    } else if (did === undefined && alias !== undefined) {
      where = { alias }
    } else {
      throw Error('[issuer:stores] Get requires did or (alias and provider)')
    }

    const identifier = await (await getDbConnection()).getRepository(Identifier).findOne({
      where,
      relations: ['keys'],
    })
    if (!identifier) throw Error('Identifier not found')

      const result: IIdentifier = {
      did: identifier.did,
      controllerKeyId: identifier.controllerKeyId,
      provider: identifier.provider!!,
      services: [],
      keys: identifier.keys.map(
        (k:Key) =>
          ({
            kid: k.kid,
            type: k.type,
            kms: k.kms,
            publicKeyHex: k.publicKeyHex,
            meta: k.meta,
          } as IKey),
      ),
    }
    if (identifier.alias) {
      result.alias = identifier.alias
    }
    return result
  }

  async deleteDID({ did }: { did: string }) {
    const identifier = await (await getDbConnection()).getRepository(Identifier).findOne({
      where: { did },
      relations: ['keys', 'services', 'issuedCredentials', 'issuedPresentations'],
    })
    if (!identifier || typeof identifier === 'undefined') {
      return true
    }

    //unlink existing keys that are no longer tied to this identifier
    let existingKeys = identifier.keys.map((key:Key) => {
      delete key.identifier
      return key
    })
    await (await getDbConnection()).getRepository(Key).save(existingKeys)

    debug('Deleting', did);
    await (await getDbConnection()).getRepository(Identifier).remove(identifier)

    return true
  }

  async importDID(args: IIdentifier) {
    const identifier = new Identifier()
    identifier.did = args.did
    if (args.controllerKeyId) {
      identifier.controllerKeyId = args.controllerKeyId
    }
    identifier.provider = args.provider
    if (args.alias) {
      identifier.alias = args.alias
    }

    identifier.keys = []
    for (const argsKey of args.keys) {
      const key = new Key()
      key.kid = argsKey.kid
      key.publicKeyHex = argsKey.publicKeyHex
      key.kms = argsKey.kms
      key.meta = argsKey.meta
      key.identifier = identifier;
      identifier.keys.push(key)
    }

    debug('Saving did', args.did)
    await (await getDbConnection()).getRepository(Identifier).save(identifier)

    return true
  }

  async listDIDs(args: { alias?: string; provider?: string }): Promise<IIdentifier[]> {
    const where: any = { provider: args?.provider || Not(IsNull()) }
    if (args?.alias) {
      where['alias'] = args.alias
    }
    const identifiers = await (await getDbConnection()).getRepository(Identifier).find({
      where,
      relations: ['keys'],
    })
    return identifiers.map((identifier) => {
      const i = identifier
      if (i.alias === null) {
        delete i.alias
      }
      return (i as unknown) as IIdentifier;
    })
  }
}
