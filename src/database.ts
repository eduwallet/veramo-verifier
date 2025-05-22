import { DataSource } from 'typeorm';
import { dbConfig } from './dbConfig';

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

  if (dataSources.has(dbConfig.schema)) {
    return dataSources.get(dbConfig.schema)
  }

  const dataSource = await new DataSource({ ...dbConfig, name: dbConfig.schema }).initialize()
  dataSources.set(dbConfig.schema, dataSource)
  if (!dbConfig.migrationsRun) {
    await dataSource.runMigrations()
  }
  return dataSource
}
