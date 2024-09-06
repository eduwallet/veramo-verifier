import Debug from 'debug';
import { Request, Response } from 'express'
import { sendErrorResponse } from '@sphereon/ssi-express-support'
import { Verifier } from 'verifier/Verifier';

const debug = Debug("verifier:receiveResponse");

export function receiveResponse(verifier:Verifier, responsePath:string) {
    verifier.router!.post(
        responsePath,
        async (request: Request, response: Response) => {
            try {
                const state = request.params.state
                const rp = verifier.sessions[state];
                if (!rp) {
                    debug.log('no state for this response');
                    return sendErrorResponse(response, 404, 'No authorization request could be found');
                }

                try {
                    await rp.processResponse(request.body.state, request.body.vp_token, JSON.parse(request.body.presentation_submission));
                }
                catch (e) {
                    console.log(e);
                }
                response.statusCode = 200
                return response.end();
            } catch (e) {
                return sendErrorResponse(response, 500, 'Could not process response', e);
            }
        }
    );
}