import Debug from 'debug';
import { Request, Response } from 'express'
import { sendErrorResponse } from '../sendErrorResponse';
import { Verifier } from 'verifier/Verifier';
import { AuthorizationResponse } from 'types/authresponse';
import { RPStatus } from 'verifier/RP';

const debug = Debug("verifier:receiveResponse");

export function receiveResponse(verifier:Verifier, responsePath:string) {
    verifier.router!.post(
        responsePath,
        async (request: Request<AuthorizationResponse>, response: Response) => {
            try {
                debug("receiving auth response", verifier.name, request.params);
                const state = request.params.state;
                const session = await verifier.sessionManager.get(state!);
                const rp = session.data.rp;
                if (!rp || rp.status != RPStatus.RETRIEVED) {
                    debug.log('no state for this response');
                    return sendErrorResponse(response, 404, 'No authorization request could be found');
                }

                try {
                    // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-5.6
                    // "When supplied as the response_type parameter in an Authorization Request, a successful response MUST include the vp_token parameter."
                    await rp.processResponse(request.body.state, request.body as AuthorizationResponse, JSON.parse(request.body.presentation_submission));
                    session.data.result = rp.result;
                    debug("parsing results in ", rp.result);
                }
                catch (e) {
                    console.log(e);
                }
                await verifier.sessionManager.set(session);
                response.statusCode = 200
                return response.end();
            } catch (e) {
                return sendErrorResponse(response, 500, 'Could not process response', e);
            }
        }
    );
}