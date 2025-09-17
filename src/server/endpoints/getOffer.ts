import Debug from 'debug';
import { Request, Response } from 'express'
import { sendErrorResponse } from '../sendErrorResponse';
import { Verifier } from 'verifier/Verifier';
import { RPStatus } from 'verifier/RP';

const debug = Debug("verifier:getOffer");

export function getOffer(verifier: Verifier, offerPath: string) {
    debug("creating route for getOffer at ", offerPath);
    verifier.router!.get(offerPath,
        async (request: Request, response: Response<string>) => {
            try {
                debug("receiving request for offer");
                const state = request.params.state;
                const session = await verifier.sessionManager.get(state);
                const rp = session.data.rp;
                if (!rp) {
                    console.log('no state for this request');
                    return sendErrorResponse(response, 404, 'No authorization request could be found');
                }

                // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-5.10
                // optional wallet_nonce in the request_uri call must be reflected in the authorization request
                if (request.params.wallet_nonce) {
                    rp.authorizationRequest.wallet_nonce = request.params.wallet_nonce;
                }

                debug("sending", rp.authorizationRequest);
                // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-5.10.1
                // "The Request URI response MUST be an HTTP response with the content type application/oauth-authz-req+jwt"
                const token = await rp.toJWT(rp.authorizationRequest, 'oauth-authz-req+jwt');
                rp.status = RPStatus.RETRIEVED;
                await verifier.sessionManager.set(session);
                response.statusCode = 200
                return response.end(token);
            } catch (e) {
                return sendErrorResponse(response, 500, 'Could not get authorization request', e);
            }
        });
}
  