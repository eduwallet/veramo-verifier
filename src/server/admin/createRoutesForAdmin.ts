import passport from 'passport';
import { Strategy } from 'passport-http-bearer';
import express, { Express } from 'express'
import { createIdentifier, deleteIdentifier, listIdentifiers, storeIdentifier } from './identifiers';
import { createPresentation, deletePresentation, listPresentations, storePresentation } from './presentations';
import { createVerifier, deleteVerifier, listVerifiers, storeVerifier } from './verifiers';
import { adminBearerToken, hasAdminBearerToken } from '@utils/adminBearerToken';
import { getVersion } from './getVersion';

function bearerAdminForAPI() {
    passport.use('admin-api', new Strategy(
        function (token:string, done:Function) {
            if (token == adminBearerToken()) {
                return done(null, true);
            }
            return done(null, false);
        }
    ));
}

export async function createRoutesForAdmin(app:Express) {
    const router = express.Router();
    app.use('/api', router);
    router.get('/version', getVersion);
    
    // no BEARER_TOKEN means no administration api
    if (!hasAdminBearerToken()) {
        return;
    }
    
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


    router.get('/presentations', 
        passport.authenticate('admin-api', { session: false }),
        listPresentations
    );
    router.post('/presentations', 
        passport.authenticate('admin-api', { session: false }),
        storePresentation
    );
    router.delete('/presentations', 
        passport.authenticate('admin-api', { session: false }),
        deletePresentation
    );
    router.put('/presentations', 
        passport.authenticate('admin-api', { session: false }),
        createPresentation
    );

    router.get('/verifiers', 
        passport.authenticate('admin-api', { session: false }),
        listVerifiers
    );
    router.post('/verifiers', 
        passport.authenticate('admin-api', { session: false }),
        storeVerifier
    );
    router.delete('/verifiers', 
        passport.authenticate('admin-api', { session: false }),
        deleteVerifier
    );
    router.put('/verifiers', 
        passport.authenticate('admin-api', { session: false }),
        createVerifier
    );
}

