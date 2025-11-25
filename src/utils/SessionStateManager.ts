import moment from 'moment';
import { createUniqueId } from '#root/utils/createUniqueId';
import { getDbConnection } from '#root/database';
import { Session } from '#root/packages/datastore/entities/Session';
import { LessThan } from 'typeorm';

export class SessionStateManager {
    private verifier:string = '';

    public constructor(verifier:string)
    {
        this.verifier = verifier;
    }

    public async clear(id: string) {
        if (!id) {
            throw Error('No state id supplied');
        }
        
        const dbConnection = await getDbConnection();
        const repo = dbConnection.getRepository(Session);
        await repo.delete({uuid: id, verifier: this.verifier});
    }

    public async get(id:string, callbackIfNotFound?:Function):Promise<Session> {
        const dbConnection = await getDbConnection();
        const repo = dbConnection.getRepository(Session);
        let session = await repo.findOneBy({uuid: id, verifier: this.verifier});

        if (!session) {
            session = this.newState();
            session.data = {};
            if (callbackIfNotFound) {
                session.data = callbackIfNotFound(session.data);
            }
        }
        return session;
    }

    public async set(state:Session)
    {
        const dbConnection = await getDbConnection();
        const repo = dbConnection.getRepository(Session);
        state.verifier = this.verifier;
        await repo.save(state);
    }

    public newState():Session {
        // create a Session entity object to ensure the decorators and callbacks of TypeORM are called
        const session:Session = new Session();
        session.uuid = createUniqueId();
        session.verifier = this.verifier;
        session.expirationDate = moment().add(4, 'hours').toDate();
        session.data = {};
        return session;
    }

    public async clearAll()
    {
        const dbConnection = await getDbConnection();
        const repo = dbConnection.getRepository(Session);
        await repo.delete({
            expirationDate: LessThan(new Date()),
            verifier: this.verifier
        });
    }
}