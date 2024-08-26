import Debug from 'debug'
import { DataSource } from 'typeorm'
import { Entities as VeramoDataStoreEntities, migrations as VeramoDataStoreMigrations } from '@veramo/data-store'
import { PostgresConnectionOptions } from 'typeorm/driver/postgres/PostgresConnectionOptions'

const debug = Debug(`verifier:db`)
const schema = process.env.DB_SCHEMA || 'verifier';
const database = process.env.DB_NAME || 'postgres';
const user = process.env.DB_USER || 'postgres';
const password = process.env.DB_PASSWORD || 'postgres';
const port = parseInt(process.env.DB_PORT || '5432');
const host = process.env.DB_HOST || 'localhost';

const dbConfig: PostgresConnectionOptions = {
  type: 'postgres',
  schema: schema,
  host: host,
  port: port,
  username: user,
  password: password,
  database: database,
  applicationName: schema,
  entities: [
    ...VeramoDataStoreEntities,
  ],
  migrations: [
    ...VeramoDataStoreMigrations,
  ],
  migrationsRun: false, // We run migrations from code to ensure proper ordering with Redux
  synchronize: false, // We do not enable synchronize, as we use migrations from code
  migrationsTransactionMode: 'each', // protect every migration with a separate transaction
  logging: 'all', //['info', 'error'], // 'all' means to enable all logging
  logger: 'advanced-console',
}

/**
 * Todo, move to a class
 */
const dataSources = new Map()

export const getDbConnection = async (): Promise<DataSource> => {
  if (dbConfig.synchronize) {
    return Promise.reject(
      `WARNING: Migrations need to be enabled in this app! Adjust the database configuration and set migrationsRun and synchronize to false`
    )
  }

  if (dataSources.has(schema)) {
    return dataSources.get(schema)
  }

  const dataSource = await new DataSource({ ...dbConfig, name: schema }).initialize()
  dataSources.set(schema, dataSource)
  if (dbConfig.migrationsRun) {
    debug(
      `Migrations are currently managed from config. Please set migrationsRun and synchronize to false to get consistent behaviour. We run migrations from code explicitly`
    )
  } else {
    debug(`Running ${dataSource.migrations.length} migration(s) from code if needed...`)
    await dataSource.runMigrations()
    debug(`${dataSource.migrations.length} migration(s) from code were inspected and applied`)
  }
  return dataSource
}
