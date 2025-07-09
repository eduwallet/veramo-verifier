import {
  Entity,
  Column,
  PrimaryColumn,
  BaseEntity,
  OneToMany,
  Index,
  BeforeInsert,
  BeforeUpdate,
} from 'typeorm'
import { Key } from '#root/packages/datastore/index'

@Entity('identifier')
@Index(['alias', 'provider'], { unique: true })
export class Identifier extends BaseEntity {
  @PrimaryColumn('varchar')
  // @ts-ignore
  did: string

  @Column({ type: 'varchar', nullable: true })
  // @ts-ignore
  provider?: string

  @Column({ type: 'varchar', nullable: true })
  // @ts-ignore
  alias?: string

  @BeforeInsert()
  setSaveDate() {
    this.saveDate = new Date()
    this.updateDate = new Date()
  }

  @BeforeUpdate()
  setUpdateDate() {
    this.updateDate = new Date()
  }

  @Column({ type: 'timestamp', select: false })
  // @ts-ignore
  saveDate: Date

  @Column({ type: 'timestamp', select: false })
  // @ts-ignore
  updateDate: Date

  @Column({ type: 'varchar', nullable: true })
  // @ts-ignore
  controllerKeyId?: string

  @OneToMany(() => Key, (key:Key) => key.identifier, { cascade: true })
  // @ts-ignore
  keys: Key[]
}
