import { MigrationInterface, QueryRunner, Table } from 'typeorm'
import { migrationGetTableName } from './migration-functions'

/**
 * Create the database layout for Veramo 3.0
 *
 * @public
 */
export class CreateDatabase1717127220001 implements MigrationInterface {
  name = 'CreateDatabase1717127220001';

  async up(queryRunner: QueryRunner): Promise<void> {
    const dateTimeType: string = queryRunner.connection.driver.mappedDataTypes.createDate as string

    await queryRunner.createTable(
      new Table({
        name: migrationGetTableName(queryRunner, 'identifier'),
        columns: [
          { name: 'did', type: 'varchar', isPrimary: true },
          { name: 'provider', type: 'varchar', isNullable: true },
          { name: 'alias', type: 'varchar', isNullable: true },
          { name: 'saveDate', type: dateTimeType },
          { name: 'updateDate', type: dateTimeType },
          { name: 'controllerKeyId', type: 'varchar', isNullable: true },
        ],
        indices: [
          {
            columnNames: ['alias', 'provider'],
            isUnique: true,
          },
        ],
      }),
      true,
    )

    await queryRunner.createTable(
      new Table({
        name: migrationGetTableName(queryRunner, 'key'),
        columns: [
          { name: 'kid', type: 'varchar', isPrimary: true },
          { name: 'kms', type: 'varchar' },
          { name: 'type', type: 'varchar' },
          { name: 'publicKeyHex', type: 'varchar' },
          { name: 'meta', type: 'text', isNullable: true },
          { name: 'identifierDid', type: 'varchar', isNullable: true },
        ],
        foreignKeys: [
          {
            columnNames: ['identifierDid'],
            referencedColumnNames: ['did'],
            referencedTableName: migrationGetTableName(queryRunner, 'identifier'),
          },
        ],
      }),
      true,
    )

    await queryRunner.createTable(
      new Table({
        name: migrationGetTableName(queryRunner, 'private-key'),
        columns: [
          {
            name: 'alias',
            type: 'varchar',
            isPrimary: true,
          },
          {
            name: 'type',
            type: 'varchar',
          },
          {
            name: 'privateKeyHex',
            type: 'varchar',
          },
        ],
      }),
      true,
    )    
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    if (await queryRunner.hasTable('private-key')) {
      await queryRunner.dropTable('private-key', true, true, true);
    }
    if (await queryRunner.hasTable('key')) {
      await queryRunner.dropTable('key', true, true, true);
    }
    if (await queryRunner.hasTable('identifier')) {
      await queryRunner.dropTable('identifier', true, true, true);
    }
  }
}
