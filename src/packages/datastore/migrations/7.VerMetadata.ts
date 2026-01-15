import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm'
import { migrationGetTableName } from './migration-functions.js'
import { PrivateKey } from '../entities/PrivateKey.js';
import { getDbConnection } from '../../../database.js';

export class VerMetadata1768311183222 implements MigrationInterface {
  name = 'VerMetadata1768311183222';
  public transaction = false;

  async up(queryRunner: QueryRunner): Promise<void> {
    if (!await queryRunner.hasColumn(migrationGetTableName(queryRunner, 'verifier'), 'metadata')) {
      await queryRunner.addColumn(
          migrationGetTableName(queryRunner, 'verifier'),
          new TableColumn({ name: 'metadata', type: 'text', isNullable: true})
      );
    }
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    if (await queryRunner.hasColumn(migrationGetTableName(queryRunner, 'verifier'), 'metadata')) {
      await queryRunner.dropColumn(migrationGetTableName(queryRunner, 'verifier'), 'metadata');
    }
  }
}
