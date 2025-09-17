import { Entity, Column, PrimaryColumn, BaseEntity } from 'typeorm'

@Entity('private-key')
export class PrivateKey extends BaseEntity {
  @PrimaryColumn('varchar')
    // @ts-ignore
  alias: string

  @Column('varchar')
    // @ts-ignore
  type: string

  @Column('varchar')
    // @ts-ignore
  privateKeyHex: string
}
