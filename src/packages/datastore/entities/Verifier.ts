import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  BaseEntity,
  Index,
  BeforeInsert,
  BeforeUpdate,
} from 'typeorm'

@Entity('verifier')
export class Verifier extends BaseEntity {
    @PrimaryGeneratedColumn('increment')
    //@ts-ignore
    id: number;

    @Column({ type: 'varchar'})
    // @ts-ignore
    name: string

    @Column({ type: 'varchar'})
    // @ts-ignore
    path: string

    @Column('varchar')
    // @ts-ignore
    did: string

    @Column('varchar')
    // @ts-ignore
    admin_token: string

    @Column('text')
    // @ts-ignore
    presentations: string

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
