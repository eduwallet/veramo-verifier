import Debug from 'debug'
import { getEnv } from 'utils/getEnv';
import { DataSource } from 'typeorm'
import { migrations } from './migrations/index'
import { PostgresConnectionOptions } from 'typeorm/driver/postgres/PostgresConnectionOptions'
import { Identifier, Key, Presentation, PrivateKey, Session, Verifier } from './entities';

const debug = Debug(`verifier:db`)
const schema = getEnv('DB_SCHEMA', 'verifier');
const database = getEnv('DB_NAME', 'postgres');
const user = getEnv('DB_USER', 'postgres');
const password = getEnv('DB_PASSWORD', 'postgres');
const port = parseInt(getEnv('DB_PORT','5432'));
const host = getEnv('DB_HOST', 'localhost');

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
    Identifier, Key, Presentation, PrivateKey, Session, Verifier
  ],
  migrations: [
    ...migrations,
  ],
  migrationsRun: false, // We run migrations from code to ensure proper ordering with Redux
  synchronize: false, // We do not enable synchronize, as we use migrations from code
  migrationsTransactionMode: 'each', // protect every migration with a separate transaction
  logging: 'all', //['info', 'error'], // 'all' means to enable all logging
  logger: 'advanced-console',
}

export class Database {
  public dataSource:DataSource|null = null;

  async initialise() {
    if (this.dataSource) {
      return this.dataSource;
    }

    if (dbConfig.synchronize) {
      return Promise.reject(
        `WARNING: Migrations need to be enabled in this app! Adjust the database configuration and set migrationsRun and synchronize to false`
      )
    }
    this.dataSource = await new DataSource({ ...dbConfig, name: schema }).initialize()

    if (dbConfig.migrationsRun) {
      debug(`Migrations are currently managed from config. Please set migrationsRun and synchronize to false to get consistent behaviour. We run migrations from code explicitly`);
    }
    else {
      debug(`Running ${this.dataSource.migrations.length} migration(s) from code if needed...`)
      await this.dataSource.runMigrations()
      debug(`${this.dataSource.migrations.length} migration(s) from code were inspected and applied`)
    }
    return this.dataSource;
    
  }
}

const _db = new Database();
export const getDbConnection = ():DataSource => { return _db.dataSource!; }
export const getDb = ():Database => {
  return _db;
}