import { Entity, Column, PrimaryColumn, BaseEntity, ManyToOne, Relation } from 'typeorm'
import { Identifier } from './Identifier.js'

@Entity('key')
export class Key extends BaseEntity {
  @PrimaryColumn('varchar')
  //@ts-expect-error has no initializer
  kid: string

  @Column('varchar')
  //@ts-expect-error has no initializer
  kms: string

  @Column('varchar')
  //@ts-expect-error has no initializer
  type: string

  @Column('varchar')
  //@ts-expect-error has no initializer
  publicKeyHex: string

  @Column({
    type: 'simple-json',
    nullable: true,
  })
  meta?: any

  @ManyToOne(() => Identifier, (identifier:Identifier) => identifier?.keys, { onDelete: 'CASCADE' })
  identifier?: Relation<Identifier>
}
