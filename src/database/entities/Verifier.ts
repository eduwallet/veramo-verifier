import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  BaseEntity,
  BeforeInsert,
  BeforeUpdate,
} from 'typeorm'

@Entity('verifier')
export class Verifier extends BaseEntity {
    @PrimaryGeneratedColumn('increment')
    //@ts-expect-error has no initializer
    id: number;

    @Column({ type: 'varchar'})
    //@ts-expect-error has no initializer
    name: string

    @Column({ type: 'varchar'})
    //@ts-expect-error has no initializer
    path: string

    @Column('varchar')
    //@ts-expect-error has no initializer
    did: string

    @Column('varchar')
    //@ts-expect-error has no initializer
    admin_token: string

    @Column('text')
    //@ts-expect-error has no initializer
    presentations: string

    @Column('text')
    //@ts-expect-error has no initializer
    metadata: string

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
