import { MigrationInterface, QueryRunner, Table } from 'typeorm'
import { migrationGetTableName } from './migration-functions.js'

export class Sessions1764077942111 implements MigrationInterface {
  name = 'Sessions1764077942111';
  public transaction = false;

  async up(queryRunner: QueryRunner): Promise<void> {
    const dateTimeType: string = queryRunner.connection.driver.mappedDataTypes.createDate as string;
    await queryRunner.createTable(
        new Table({
          name: migrationGetTableName(queryRunner, 'session'),
          columns: [
            { name: 'id', type: "int", isPrimary: true, isGenerated: true, generationStrategy: "increment" },
            { name: 'uuid', type: 'varchar', isNullable: true},
            { name: 'state', type: 'varchar', isNullable: true},
            { name: 'verifier', type: 'varchar', isNullable: true},
            { name: 'expirationDate', type: dateTimeType, isNullable: true },
            { name: 'saveDate', type: dateTimeType },
            { name: 'updateDate', type: dateTimeType },
            { name: 'data', type: 'text', isNullable: true }
          ],
        }),
        true,
      );
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    if (await queryRunner.hasTable('session')) {
        await queryRunner.dropTable('session', true, true, true);
    }
  }
}
