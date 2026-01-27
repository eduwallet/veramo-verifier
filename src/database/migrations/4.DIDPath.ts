import { MigrationInterface, QueryRunner, Table, TableColumn } from 'typeorm'
import { migrationGetTableName } from './migration-functions.js'

export class DIDPath1760691999150 implements MigrationInterface {
  name = 'DIDPath1760691999150';

  async up(queryRunner: QueryRunner): Promise<void> {
    if (!await queryRunner.hasColumn(migrationGetTableName(queryRunner, 'identifier'), 'path')) {
      await queryRunner.addColumn(
          migrationGetTableName(queryRunner, 'identifier'),
          new TableColumn({ name: 'path', type: 'varchar', isNullable: true})
      );
    }
    if (!await queryRunner.hasColumn(migrationGetTableName(queryRunner, 'identifier'), 'services')) {
      await queryRunner.addColumn(
          migrationGetTableName(queryRunner, 'identifier'),
          new TableColumn({ name: 'services', type: 'text', isNullable: true})
      );
    }
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    if (await queryRunner.hasColumn(migrationGetTableName(queryRunner, 'identifier'), 'path')) {
      await queryRunner.dropColumn(migrationGetTableName(queryRunner, 'identifier'), 'path');
    }
    if (await queryRunner.hasColumn(migrationGetTableName(queryRunner, 'identifier'), 'services')) {
      await queryRunner.dropColumn(migrationGetTableName(queryRunner, 'identifier'), 'services');
    }
  }
}
