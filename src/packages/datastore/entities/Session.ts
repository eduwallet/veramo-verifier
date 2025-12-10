import { StringKeyedObject } from '#root/types/index';
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
    //@ts-ignore
    id: number;
    
    @Column('varchar')
    //@ts-ignore
    uuid: string

    @Column('varchar')
    //@ts-ignore
    state: string

    @Column('varchar')
    //@ts-ignore
    verifier: string

    @Column({ type: 'simple-json' })
    //@ts-ignore
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
    //@ts-ignore
    saveDate: Date

    @Column({ type: 'timestamp', select: true })
    //@ts-ignore
    updateDate: Date
}
