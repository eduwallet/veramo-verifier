import passport from 'passport';
import { Strategy } from 'passport-http-bearer';
import express, { Express } from 'express'
import { createIdentifier, deleteIdentifier, listIdentifiers, storeIdentifier } from './identifiers';

function bearerAdminForAPI() {
    passport.use('admin-api', new Strategy(
        function (token:string, done:Function) {
            if (token == process.env.BEARER_TOKEN) {
                return done(null, true);
            }
            return done(null, false);
        }
    ));
}

export async function createRoutesForAdmin(app:Express) {
    const router = express.Router();
    app.use('/api', router);
    bearerAdminForAPI();

    router.get('/exit',
        passport.authenticate('admin-api', { session: false }),
        () => {
            setTimeout(() => { process.exit(0)}, 2000);
        }
    )

    router.get('/identifiers', 
        passport.authenticate('admin-api', { session: false }),
        listIdentifiers
    );
    router.post('/identifiers', 
        passport.authenticate('admin-api', { session: false }),
        storeIdentifier
    );
    router.delete('/identifiers', 
        passport.authenticate('admin-api', { session: false }),
        deleteIdentifier
    );
    router.put('/identifiers', 
        passport.authenticate('admin-api', { session: false }),
        createIdentifier
    );
}

