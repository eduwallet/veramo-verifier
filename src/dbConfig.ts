import { getEnv } from 'utils/getEnv';
import { migrations } from './packages/datastore/migrations'
import { Entities } from './packages/datastore/entities';
import { PostgresConnectionOptions } from 'typeorm/driver/postgres/PostgresConnectionOptions'

const schema = getEnv('DB_SCHEMA', 'verifier');
const database = getEnv('DB_NAME', 'postgres');
const user = getEnv('DB_USER', 'postgres');
const password = getEnv('DB_PASSWORD', 'postgres');
const port = parseInt(getEnv('DB_PORT','5432'));
const host = getEnv('DB_HOST', 'localhost');

export const dbConfig: PostgresConnectionOptions = {
  type: 'postgres',
  schema: schema,
  host: host,
  port: port,
  username: user,
  password: password,
  database: database,
  applicationName: schema,
  entities: Entities,
  migrations,
  migrationsRun: false, // We run migrations from code to ensure proper ordering with Redux
  synchronize: false, // We do not enable synchronize, as we use migrations from code
  migrationsTransactionMode: 'each', // protect every migration with a separate transaction
  logging: 'all', //['info', 'error'], // 'all' means to enable all logging
  logger: 'advanced-console',
}
