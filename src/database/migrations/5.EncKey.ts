import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm'
import { migrationGetTableName } from './migration-functions.js'
import { PrivateKey } from '../entities/index';
import { getDbConnection } from '../index';

export class EncKey1762521078111 implements MigrationInterface {
  name = 'EncKey1762521078111';
  public transaction = false;

  async up(queryRunner: QueryRunner): Promise<void> {
    if (!await queryRunner.hasColumn(migrationGetTableName(queryRunner, 'private-key'), 'seed')) {
      await queryRunner.addColumn(
          migrationGetTableName(queryRunner, 'private-key'),
          new TableColumn({ name: 'seed', type: 'varchar', isNullable: true})
      );
    }

    if ((process.env.PASSPHRASE ?? '').length > 0) {
        const db = getDbConnection();
        const repo = db.getRepository(PrivateKey);
        const keys = await repo.createQueryBuilder('private-key').getMany();
        for (const key of keys) {
            key.setSeed();
            await key.encodeKey(key.privateKeyHex);
            await repo.save(key);
        }
    }
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    if ((process.env.PASSPHRASE ?? '').length > 0) {
        const db = getDbConnection();
        const repo = db.getRepository(PrivateKey);
        const keys = await repo.createQueryBuilder('private-key').getMany();
        for (const key of keys) {
            if (key.seed && key.seed.length > 0) {
                key.privateKeyHex = await key.decodeKey();
                await repo.save(key);
            }
        }
    }

    if (await queryRunner.hasColumn(migrationGetTableName(queryRunner, 'private-key'), 'seed')) {
      await queryRunner.dropColumn(migrationGetTableName(queryRunner, 'private-key'), 'seed');
    }
  }
}
