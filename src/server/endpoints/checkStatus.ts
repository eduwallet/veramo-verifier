import { Request, Response } from 'express'
import { sendErrorResponse } from '@sphereon/ssi-express-support'
import { Verifier } from 'verifier/Verifier';
import passport from 'passport';

interface StatusRequest {
    statusList: string;
    index: number;
}

export function checkStatus(verifier: Verifier, checkPath: string) {
    verifier.router!.post(checkPath,
        passport.authenticate(verifier.name + '-admin', { session: false }),
        async (request: Request<StatusRequest>, response: Response) => {
        try {
            const result = await verifier.statusList.checkStatus(request.body.statusList, request.body.index);
            response.send(result);
        } catch (e) {
            sendErrorResponse(response, 500, 'Could not determine RP session', e);
        }
    });
}
  