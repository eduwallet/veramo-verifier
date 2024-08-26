import passport from 'passport';
import { Strategy } from 'passport-http-bearer';
import { Verifier } from '../verifier/Verifier';

export function bearerAdminForVerifier(verifier:Verifier) {
    passport.use(verifier.name + '-admin', new Strategy(
        function (token:string, done:Function) {
            if (token == verifier.adminToken) {
                return done(null, verifier);
            }
            return done(null, false);
        }
    ));
}
