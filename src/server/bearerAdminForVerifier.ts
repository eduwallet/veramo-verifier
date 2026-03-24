import Debug from 'debug';
import passport from 'passport';
import { Strategy } from 'passport-http-bearer';
import { Verifier } from '../verifier/Verifier';

const debug=Debug('server:bearer');

type PassportCallback = (err:any, res:any) => void;

export function bearerAdminForVerifier(verifier:Verifier) {
    passport.use(verifier.name + '-admin', new Strategy(
        function (token:string, done:PassportCallback) {
            debug('testing ', token, 'vs', verifier.adminToken,' for ', verifier.name);
            if (token == verifier.adminToken) {
                return done(null, verifier);
            }
            return done(null, false);
        }
    ));
}
