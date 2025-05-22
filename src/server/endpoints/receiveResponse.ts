import Debug from 'debug';
import { Request, Response } from 'express'
import { sendErrorResponse } from '@sphereon/ssi-express-support'
import { Verifier } from 'verifier/Verifier';
import { openObserverLog } from '@utils/openObserverLog';

const debug = Debug("verifier:receiveResponse");

export function receiveResponse(verifier:Verifier, responsePath:string) {
    verifier.router!.post(
        responsePath,
        async (request: Request, response: Response) => {
            try {
                debug("receiving auth response", verifier.name, request.params);
                const state = request.params.state
                const rp = verifier.sessions[state];
                openObserverLog(state, 'receive-response', { name: verifier.name, request: request.params});
                if (!rp) {
                    openObserverLog(state, 'receive-response', { error: 'no state for this request found'});
                    debug.log('no state for this response');
                    sendErrorResponse(response, 404, 'No authorization request could be found');
                }

                try {
                    await rp.processResponse(request.body.state, request.body.vp_token, JSON.parse(request.body.presentation_submission));
                }
                catch (e) {
                    openObserverLog(state, 'receive-response', { error: JSON.stringify(e) });
                    console.log(e);
                }
                response.statusCode = 200
                openObserverLog(state, 'receive-response', { name: verifier.name, status: 200});
                response.end();
            } catch (e) {
                openObserverLog('none', 'receive-response', { error: JSON.stringify(e) });
                sendErrorResponse(response, 500, 'Could not process response', e);
            }
        }
    );
}