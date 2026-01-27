import { MigrationInterface, QueryRunner, Table } from 'typeorm'
import { migrationGetTableName } from './migration-functions.js'

export class Verifiers1759493650000 implements MigrationInterface {
  name = 'Verifiers1759493650000';

  async up(queryRunner: QueryRunner): Promise<void> {
    const dateTimeType: string = queryRunner.connection.driver.mappedDataTypes.createDate as string

    await queryRunner.createTable(
        new Table({
          name: migrationGetTableName(queryRunner, 'verifier'),
          columns: [
            { name: 'id', type: "int", isPrimary: true, isGenerated: true, generationStrategy: "increment" },
            { name: 'name', type: 'varchar', isNullable: false},
            { name: 'path', type: 'varchar', isNullable: false},
            { name: 'did', type: 'varchar', length: '1024', isNullable: false},
            { name: 'admin_token', type: 'varchar', isNullable: false},
            { name: 'presentations', type: 'text', isNullable: false},
            { name: 'saveDate', type: dateTimeType },
            { name: 'updateDate', type: dateTimeType }
          ],
        }),
        true,
      );
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    if (await queryRunner.hasTable('verifier')) {
        await queryRunner.dropTable('verifier', true, true, true);
    }
  }
}
