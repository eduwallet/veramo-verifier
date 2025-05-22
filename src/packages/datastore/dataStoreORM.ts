import {
  FindArgs,
  IAgentPlugin,
  IDataStoreORM,
  IIdentifier,
  PartialIdentifier,
  TClaimsColumns,
  TCredentialColumns,
  TIdentifiersColumns,
  TMessageColumns,
  TPresentationColumns,
} from '@veramo/core-types'
import { schema } from '@veramo/core-types'
import { Identifier } from './entities/Identifier'
import {
  Any,
  Between,
  Equal,
  In,
  IsNull,
  LessThan,
  LessThanOrEqual,
  Like,
  MoreThan,
  MoreThanOrEqual,
  Not,
  SelectQueryBuilder,
} from 'typeorm'
import { getDbConnection } from '../../database';

/**
 * This class implements the {@link @veramo/core-types#IDataStoreORM} query interface using a TypeORM compatible database.
 *
 * This allows you to filter Verifiable Credentials, Presentations and Messages by some common properties that are
 * parsed and stored in database tables.
 *
 * This class is designed to work with {@link @veramo/data-store#DataStore} which is the default way to populate the
 * database with Credentials, Presentations and Messages in such a way that they can be queried by this class.
 * These two classes MUST also share the same database connection.
 *
 * @see {@link @veramo/core-types#IDataStoreORM}
 * @see {@link @veramo/core-types#IDataStore}
 *
 * @beta This API may change without a BREAKING CHANGE notice.
 */
export class DataStoreORM implements IAgentPlugin {
  readonly methods: IDataStoreORM
  readonly schema = schema.IDataStoreORM

  constructor() {
    this.methods = {
      dataStoreORMGetIdentifiers: this.dataStoreORMGetIdentifiers.bind(this),
      dataStoreORMGetIdentifiersCount: this.dataStoreORMGetIdentifiersCount.bind(this),
      dataStoreORMGetMessages: this.notImplemented.bind(this),
      dataStoreORMGetMessagesCount: this.notImplemented.bind(this),
      dataStoreORMGetVerifiableCredentialsByClaims:this.notImplemented.bind(this),
      dataStoreORMGetVerifiableCredentialsByClaimsCount:this.notImplemented.bind(this),
      dataStoreORMGetVerifiableCredentials: this.notImplemented.bind(this),
      dataStoreORMGetVerifiableCredentialsCount: this.notImplemented.bind(this),
      dataStoreORMGetVerifiablePresentations: this.notImplemented.bind(this),
      dataStoreORMGetVerifiablePresentationsCount:this.notImplemented.bind(this),
    }
  }

  async notImplemented(): Promise<any>
  {
    throw new Error("method not implemented");
  }

  // Identifiers

  private async identifiersQuery(
    args: FindArgs<TIdentifiersColumns>,
  ): Promise<SelectQueryBuilder<Identifier>> {
    const where = createWhereObject(args)
    let qb = (await getDbConnection())
      .getRepository(Identifier)
      .createQueryBuilder('identifier')
      .leftJoinAndSelect('identifier.keys', 'keys')
      .where(where)
    qb = decorateQB(qb, 'message', args)
    return qb
  }

  async dataStoreORMGetIdentifiers(
    args: FindArgs<TIdentifiersColumns>,
  ): Promise<PartialIdentifier[]> {
    const identifiers = await (await this.identifiersQuery(args)).getMany()
    return identifiers.map((i) => {
      const identifier: PartialIdentifier = i as PartialIdentifier
      if (identifier.controllerKeyId === null) {
        delete identifier.controllerKeyId
      }
      if (identifier.alias === null) {
        delete identifier.alias
      }
      if (identifier.provider === null) {
        delete identifier.provider
      }
      return identifier as IIdentifier
    })
  }

  async dataStoreORMGetIdentifiersCount(
    args: FindArgs<TIdentifiersColumns>,
  ): Promise<number> {
    return await (await this.identifiersQuery(args)).getCount()
  }
}

function createWhereObject(
  input: FindArgs<
    TMessageColumns | TClaimsColumns | TCredentialColumns | TPresentationColumns | TIdentifiersColumns
  >,
): any {
  const where: Record<string, any> = {}
  if (input?.where) {
    for (const item of input.where) {
      if (item.column === 'verifier') {
        continue
      }
      switch (item.op) {
        case 'Any':
          if (!Array.isArray(item.value)) throw Error('Operator Any requires value to be an array')
          where[item.column] = Any(item.value)
          break
        case 'Between':
          if (item.value?.length != 2) throw Error('Operation Between requires two values')
          where[item.column] = Between(item.value[0], item.value[1])
          break
        case 'Equal':
          if (item.value?.length != 1) throw Error('Operation Equal requires one value')
          where[item.column] = Equal(item.value[0])
          break
        case 'IsNull':
          where[item.column] = IsNull()
          break
        case 'LessThan':
          if (item.value?.length != 1) throw Error('Operation LessThan requires one value')
          where[item.column] = LessThan(item.value[0])
          break
        case 'LessThanOrEqual':
          if (item.value?.length != 1) throw Error('Operation LessThanOrEqual requires one value')
          where[item.column] = LessThanOrEqual(item.value[0])
          break
        case 'Like':
          if (item.value?.length != 1) throw Error('Operation Like requires one value')
          where[item.column] = Like(item.value[0])
          break
        case 'MoreThan':
          if (item.value?.length != 1) throw Error('Operation MoreThan requires one value')
          where[item.column] = MoreThan(item.value[0])
          break
        case 'MoreThanOrEqual':
          if (item.value?.length != 1) throw Error('Operation MoreThanOrEqual requires one value')
          where[item.column] = MoreThanOrEqual(item.value[0])
          break
        case 'In':
        default:
          if (!Array.isArray(item.value)) throw Error('Operator IN requires value to be an array')
          where[item.column] = In(item.value)
      }
      if (item.not === true) {
        where[item.column] = Not(where[item.column])
      }
    }
  }
  return where
}

function decorateQB(
  qb: SelectQueryBuilder<any>,
  tableName: string,
  input: FindArgs<any>,
): SelectQueryBuilder<any> {
  if (input?.skip) qb = qb.offset(input.skip)
  if (input?.take) qb = qb.limit(input.take)

  if (input?.order) {
    for (const item of input.order) {
      qb = qb.addSelect(
        qb.connection.driver.escape(tableName) + '.' + qb.connection.driver.escape(item.column),
        item.column,
      )
      qb = qb.orderBy(qb.connection.driver.escape(item.column), item.direction)
    }
  }
  return qb
}
