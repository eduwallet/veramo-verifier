import Debug from 'debug';
import { Request, Response } from 'express'
import { sendErrorResponse } from '@sphereon/ssi-express-support'

import { StatusList, StatusRequest } from 'statuslist/StatusList';
import { Verifier } from 'verifier/Verifier';
import passport from 'passport';
import dayjs from 'dayjs';
import { RPStatus, VPResult } from 'verifier/RP';

interface CheckStatusResponse {
    status: string;
}

export function checkStatus(verifier: Verifier, checkPath: string) {
    verifier.router!.post(checkPath,
        passport.authenticate(verifier.name + '-admin', { session: false }),
        async (request: Request, response: Response<CheckStatusResponse>) => {
        try {
            const responseObject:CheckStatusResponse = {
                status: 'VALID'
            };
            const result = await StatusList.checkStatus(request.body as StatusRequest);
            if (!result) {
                responseObject.status = 'INVALID';
            }
            return response.send(responseObject);
        } catch (e) {
            return sendErrorResponse(response, 500, 'Could not determine RP session', e);
        }
    });
}
  