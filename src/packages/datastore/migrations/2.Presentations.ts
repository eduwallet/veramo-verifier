import { MigrationInterface, QueryRunner, Table } from 'typeorm'
import { migrationGetTableName } from './migration-functions.js'

export class Presentations1758721139150 implements MigrationInterface {
  name = 'Presentations1758721139150';

  async up(queryRunner: QueryRunner): Promise<void> {
    const dateTimeType: string = queryRunner.connection.driver.mappedDataTypes.createDate as string

    await queryRunner.createTable(
        new Table({
          name: migrationGetTableName(queryRunner, 'presentation'),
          columns: [
            { name: 'id', type: "int", isPrimary: true, isGenerated: true, generationStrategy: "increment" },
            { name: 'shortname', type: 'varchar', isNullable: false},
            { name: 'name', type: 'varchar', isNullable: false},
            { name: 'purpose', type: 'varchar', length: '1024', isNullable: false},
            { name: 'input_descriptors', type: 'text', isNullable: true},
            { name: 'query', type: 'text', isNullable: true},
            { name: 'saveDate', type: dateTimeType },
            { name: 'updateDate', type: dateTimeType }
          ],
        }),
        true,
      );
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    if (await queryRunner.hasTable('presentation')) {
        await queryRunner.dropTable('presentation', true, true, true);
    }
  }
}
