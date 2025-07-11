import Debug from 'debug';
import { Request, Response } from 'express'
import { sendErrorResponse } from '../sendErrorResponse';
import { Verifier } from 'verifier/Verifier';
import { openObserverLog } from '@utils/openObserverLog';
import { AuthorizationResponse } from 'types/authresponse';

const debug = Debug("verifier:receiveResponse");

export function receiveResponse(verifier:Verifier, responsePath:string) {
    verifier.router!.post(
        responsePath,
        async (request: Request<AuthorizationResponse>, response: Response) => {
            try {
                debug("receiving auth response", verifier.name, request.params);
                const state = request.params.state
                const rp = verifier.sessions[state];
                openObserverLog(state, 'receive-response', { name: verifier.name, request: request.params});
                if (!rp) {
                    openObserverLog(state, 'receive-response', { error: 'no state for this request found'});
                    debug.log('no state for this response');
                    return sendErrorResponse(response, 404, 'No authorization request could be found');
                }

                try {
                    // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-5.6
                    // "When supplied as the response_type parameter in an Authorization Request, a successful response MUST include the vp_token parameter."
                    await rp.processResponse(request.body.state, request.body as AuthorizationResponse, JSON.parse(request.body.presentation_submission));
                }
                catch (e) {
                    openObserverLog(state, 'receive-response', { error: JSON.stringify(e) });
                    console.log(e);
                }
                response.statusCode = 200
                openObserverLog(state, 'receive-response', { name: verifier.name, status: 200});
                return response.end();
            } catch (e) {
                openObserverLog('none', 'receive-response', { error: JSON.stringify(e) });
                return sendErrorResponse(response, 500, 'Could not process response', e);
            }
        }
    );
}