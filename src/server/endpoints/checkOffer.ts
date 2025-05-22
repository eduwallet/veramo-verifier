import Debug from 'debug';
import { Request, Response } from 'express'
import { sendErrorResponse } from '@sphereon/ssi-express-support'

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
            const rp = verifier.sessions[request.params.state];
            if (!rp) {
                sendErrorResponse(response, 404, 'No authorization request could be found');
            }
            const responseObject:CheckOfferResponse = {
                status: rp.status,
                created: dayjs(rp.created).format(),
                lastUpdate: dayjs(rp.lastUpdate).format()
            };
            if (rp.status == RPStatus.RESPONSE) {
                responseObject.result = rp.result;
            }
            response.send(responseObject);
        } catch (e) {
            sendErrorResponse(response, 500, 'Could not determine RP session', e);
        }
    });
}
  