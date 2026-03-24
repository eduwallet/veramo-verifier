import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  BaseEntity,
  BeforeInsert,
  BeforeUpdate,
} from 'typeorm'

@Entity('presentation')
export class Presentation extends BaseEntity {
    @PrimaryGeneratedColumn('increment')
    //@ts-expect-error has no initializer
    id: number;

    @Column({ type: 'varchar'})
    //@ts-expect-error has no initializer
    shortname: string

    @Column({ type: 'varchar'})
    //@ts-expect-error has no initializer
    name: string

    @Column('varchar')
    //@ts-expect-error has no initializer
    purpose: string

    @Column('text')
    input_descriptors?: string

    @Column('text')
    query?: string

    @BeforeInsert()
    setSaveDate() {
        this.saveDate = new Date()
        this.updateDate = new Date()
    }

    @BeforeUpdate()
    setUpdateDate() {
        this.updateDate = new Date()
    }

    @Column({ type: 'timestamp'})
    //@ts-expect-error has no initializer
    saveDate: Date

    @Column({ type: 'timestamp'})
    //@ts-expect-error has no initializer
    updateDate: Date
}
