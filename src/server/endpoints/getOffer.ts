import Debug from 'debug';
import { Request, Response } from 'express'
import { sendErrorResponse } from '@sphereon/ssi-express-support'
import { Verifier } from 'verifier/Verifier';

const debug = Debug("verifier:getOffer");

export function getOffer(verifier: Verifier, offerPath: string) {
    debug("creating route for getOffer at ", offerPath);
    verifier.router!.get(offerPath,
        async (request: Request, response: Response<string>) => {
            try {
                const state = request.params.state
                const presentationId = request.params.presentationid
                if (!state || !presentationId) {
                    console.log(`No authorization request could be found for the given url. state: ${state}, presentationId: ${presentationId}`)
                    return sendErrorResponse(response, 404, 'No authorization request could be found')
                }

                const requestState = await verifier.sessionManager.getRequestStateByState(state, false);
                if (!requestState) {
                    debug(`No authorization request could be found for the given url in the state manager. state: ${state}, presentationId: ${presentationId}`)
                    return sendErrorResponse(response, 404, `No authorization request could be found`)
                }

                const requestObject = await requestState.request?.requestObject?.toJwt()
                debug('JWT Request object:', requestObject);

                await verifier.rp!.signalAuthRequestRetrieved({correlationId: state});

                response.statusCode = 200
                return response.end(requestObject)
            } catch (e) {
                return sendErrorResponse(response, 500, 'Could not get authorization request', e);
            }
        });
}
  