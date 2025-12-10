import Debug from 'debug';
import { Request, Response } from 'express'
import { sendErrorResponse } from '../sendErrorResponse';

import { Verifier } from 'verifier/Verifier';
import passport from 'passport';
import dayjs from 'dayjs';
import { RPStatus, VPResult } from 'verifier/RP';

const debug = Debug("verifier:createOffer");
interface CheckOfferResponse {
    status: string;
    created: string;
    lastUpdate:string;
    result?:VPResult;
}

export function checkOffer(verifier: Verifier, checkPath: string) {
    verifier.router!.get(checkPath,
        passport.authenticate(verifier.name + '-admin', { session: false }),
        async (request: Request, response: Response<CheckOfferResponse>) => {
        try {
            const session = await verifier.sessionManager.get(request.params.state);
            const responseObject:CheckOfferResponse = {
                status: session.data.status,
                created: dayjs(session.data.created).format(),
                lastUpdate: dayjs(session.data.lastUpdate).format()
            };
            if (session.data.status == RPStatus.RESPONSE) {
                responseObject.result = session.data.result;
            }
            return response.send(responseObject);
        } catch (e) {
            return sendErrorResponse(response, 500, 'Could not determine RP session', e);
        }
    });
}
  