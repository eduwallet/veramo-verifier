import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  BaseEntity,
  Index,
  BeforeInsert,
  BeforeUpdate,
} from 'typeorm'

@Entity('presentation')
export class Presentation extends BaseEntity {
    @PrimaryGeneratedColumn('increment')
    //@ts-ignore
    id: number;

    @Column({ type: 'varchar'})
    // @ts-ignore
    shortname: string

    @Column({ type: 'varchar'})
    // @ts-ignore
    name: string

    @Column('varchar')
    // @ts-ignore
    purpose: string

    @Column('text')
    // @ts-ignore
    input_descriptors: string

    @Column('text')
    // @ts-ignore
    query: string

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
    // @ts-ignore
    saveDate: Date

    @Column({ type: 'timestamp'})
    // @ts-ignore
    updateDate: Date
}
