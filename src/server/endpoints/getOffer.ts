import Debug from 'debug';
import { Request, Response } from 'express'
import { sendErrorResponse } from '@sphereon/ssi-express-support'
import { Verifier } from 'verifier/Verifier';
import { RPStatus } from 'verifier/RP';
import { openObserverLog } from '@utils/openObserverLog';

const debug = Debug("verifier:getOffer");

export function getOffer(verifier: Verifier, offerPath: string) {
    debug("creating route for getOffer at ", offerPath);
    verifier.router!.get(offerPath,
        async (request: Request, response: Response<string>) => {
            try {
                const state = request.params.state
                const rp = verifier.sessions[state];
                openObserverLog(state, 'get-offer', { name: verifier.name, request: request.params});
                if (!rp) {
                    console.log('no state for this request');
                    openObserverLog(state, 'get-offer', { error: 'no authorization request could be found'});
                    return sendErrorResponse(response, 404, 'No authorization request could be found');
                }

                await rp.toJWT(rp.authorizationRequest);
                rp.status = RPStatus.RETRIEVED;
                response.statusCode = 200
                openObserverLog(state, 'get-offer', { name: verifier.name, response: rp.authorizationRequest});
                return response.end(rp.jwt);
            } catch (e) {
                openObserverLog('none', 'get-offer', { error: JSON.stringify(e) });
                return sendErrorResponse(response, 500, 'Could not get authorization request', e);
            }
        });
}
  