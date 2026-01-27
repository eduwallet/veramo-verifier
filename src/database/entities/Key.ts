import { Entity, Column, PrimaryColumn, BaseEntity, ManyToOne, Relation } from 'typeorm'
import { Identifier } from './Identifier.js'

@Entity('key')
export class Key extends BaseEntity {
  @PrimaryColumn('varchar')
  // @ts-ignore
  kid: string

  @Column('varchar')
  // @ts-ignore
  kms: string

  @Column('varchar')
  // @ts-ignore
  type: string

  @Column('varchar')
  // @ts-ignore
  publicKeyHex: string

  @Column({
    type: 'simple-json',
    nullable: true,
  })
  meta?: any

  @ManyToOne(() => Identifier, (identifier:Identifier) => identifier?.keys, { onDelete: 'CASCADE' })
  identifier?: Relation<Identifier>
}
