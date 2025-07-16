import { Request, Response } from 'express'
import { sendErrorResponse } from '../sendErrorResponse';
import { Verifier } from 'verifier/Verifier';
import passport from 'passport';

interface StatusRequest {
    statusList: string;
    type: string;
    index: number;
    size?:number;
}

export function checkStatus(verifier: Verifier, checkPath: string) {
    verifier.router!.post(checkPath,
        passport.authenticate(verifier.name + '-admin', { session: false }),
        async (request: Request<StatusRequest>, response: Response) => {
        try {
            const result = await verifier.statusList.check({
                type: request.body.type,
                url: request.body.statusList,
                index: request.body.index,
                size: request.body.size ?? 1
            });
            return response.send(result);
        } catch (e) {
            return sendErrorResponse(response, 500, 'Could not determine RP session', e);
        }
    });
}
  