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
import { Key } from './Key'

@Entity('identifier')
@Index(['alias', 'provider'], { unique: true })
export class Identifier extends BaseEntity {
  @PrimaryColumn('varchar')
  //@ts-expect-error has no initializer
  did: string

  @Column({ type: 'varchar', nullable: true })
  provider?: string

  @Column({ type: 'varchar', nullable: true })
  alias?: string

  @Column({ type: 'varchar', nullable: true })
  path?: string

  @Column({ type: 'text', nullable: true })
  services?: string

  @BeforeInsert()
  setSaveDate() {
    this.saveDate = new Date()
    this.updateDate = new Date()
  }

  @BeforeUpdate()
  setUpdateDate() {
    this.updateDate = new Date()
  }

  @Column({ type: 'timestamp', select: true })
  //@ts-expect-error has no initializer
  saveDate: Date

  @Column({ type: 'timestamp', select: true })
  //@ts-expect-error has no initializer
  updateDate: Date

  @Column({ type: 'varchar', nullable: true })
  controllerKeyId?: string

  @OneToMany(() => Key, (key:Key) => key.identifier, { cascade: true })
  //@ts-expect-error has no initializer
  keys: Key[]
}
