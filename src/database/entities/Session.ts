import { StringKeyedObject } from 'types/index';
import {
    Entity,
    Column,
    PrimaryGeneratedColumn,
    BaseEntity,
    BeforeInsert,
    BeforeUpdate,
} from 'typeorm'

@Entity('session')
export class Session extends BaseEntity {
    @PrimaryGeneratedColumn('increment')
    //@ts-expect-error has no initializer
    id: number;
    
    @Column('varchar')
    //@ts-expect-error has no initializer
    uuid: string

    @Column('varchar')
    //@ts-expect-error has no initializer
    state: string

    @Column('varchar')
    //@ts-expect-error has no initializer
    verifier: string

    @Column({ type: 'simple-json' })
    //@ts-expect-error has no initializer
    data: StringKeyedObject;

    @Column({ type: 'timestamp', nullable: true })
    expirationDate?: Date

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
}
