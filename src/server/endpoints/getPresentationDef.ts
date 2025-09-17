import Debug from 'debug';
import { sendErrorResponse } from '../sendErrorResponse';
import { Request } from 'express'
import { Verifier } from 'verifier/Verifier';

const debug = Debug('server:presentationdef');

export function getPresentationDef(verifier:Verifier, path:string) {
    verifier.router!.get(path, async (req: Request, response) => {
        debug("getting presentation definition", verifier.name, req.params);
        const presentation = verifier.getPresentation(req.params.presentationid);
        if (!presentation) {
            return sendErrorResponse(response, 404, 'No such presentation for ' + req.params.presentationid);
        }
        debug("returning", presentation);
        return response.json(presentation);
    });
}
