import moment from 'moment';
import { createUniqueId } from '#root/utils/createUniqueId';
//import { getDbConnection } from '#root/database/databaseService';
//import { LessThan } from 'typeorm';

export interface Session {
    id: string;
    expirationDate: Date;
    data: any;
}

export class SessionStateManager {
    private _sessions:Map<string,Session>;

    public constructor()
    {
        this._sessions = new Map<string, Session>();
    }

    public async clear(id: string) {
        if (!id) {
            throw Error('No state id supplied');
        }
        
        //const dbConnection = await getDbConnection();
        //const repo = dbConnection.getRepository(Session);
        //await repo.delete({uuid: id, issuer: this.issuer});
        if (this._sessions.has(id)) {
            this._sessions.delete(id);
        }
    }

    public async get(id:string, callbackIfNotFound?:Function):Promise<Session> {
        //const dbConnection = await getDbConnection();
        //const repo = dbConnection.getRepository(Session);
        //let session = await repo.findOneBy({uuid: id, issuer: this.issuer});
        let session;
        if (this._sessions.has(id)) {
            session = this._sessions.get(id)!;
        }
        else {
            session = this.newState();
            session.data = {};
            if (callbackIfNotFound) {
                session.data = callbackIfNotFound(session.data);
            }
        }
        return session;
    }

    public async getByState(id:string):Promise<Session|null>
    {
        //const dbConnection = await getDbConnection();
        //const repo = dbConnection.getRepository(Session);
        //return await repo.findOneBy({state: id, issuer: this.issuer});
        if (this._sessions.has(id)) {
            return this._sessions.get(id)!;
        }
        return null;
    }

    public async set(state:Session)
    {
        //const dbConnection = await getDbConnection();
        //const repo = dbConnection.getRepository(Session);
        //await repo.save(state);
        this._sessions.set(state.id, state);
    }

    public newState():Session {
        const session:Session = {
            id: createUniqueId(),
            expirationDate: moment().add(4, 'hours').toDate(),
            data: {}
        };
        return session;
    }

    public async clearAll()
    {
        //const dbConnection = await getDbConnection();
        //const repo = dbConnection.getRepository(Session);
        //await repo.delete({
        //    expirationDate: LessThan(new Date()),
        //    issuer: this.issuer
        //});
        const now = new Date();
        for(const key of this._sessions.keys()) {
            const session = this._sessions.get(key)!;
            if (now > session.expirationDate) {
                this._sessions.delete(key);
            }
        }
    }
}