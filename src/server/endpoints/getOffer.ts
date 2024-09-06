import Debug from 'debug';
import { Request, Response } from 'express'
import { sendErrorResponse } from '@sphereon/ssi-express-support'
import { Verifier } from 'verifier/Verifier';
import { RPStatus } from 'verifier/RP';

const debug = Debug("verifier:getOffer");

export function getOffer(verifier: Verifier, offerPath: string) {
    debug("creating route for getOffer at ", offerPath);
    verifier.router!.get(offerPath,
        async (request: Request, response: Response<string>) => {
            try {
                const state = request.params.state
                const rp = verifier.sessions[state];
                if (!rp) {
                    console.log('no state for this request');
                    return sendErrorResponse(response, 404, 'No authorization request could be found');
                }

                await rp.toJWT(rp.authorizationRequest);
                rp.status = RPStatus.RETRIEVED;
                response.statusCode = 200
                return response.end(rp.jwt);
            } catch (e) {
                return sendErrorResponse(response, 500, 'Could not get authorization request', e);
            }
        });
}
  