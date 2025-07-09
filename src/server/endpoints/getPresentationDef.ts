import Debug from 'debug';
import { sendErrorResponse } from '../sendErrorResponse';
import { openObserverLog } from '@utils/openObserverLog';
import { Request } from 'express'
import { Verifier } from 'verifier/Verifier';

const debug = Debug('server:presentationdef');

export function getPresentationDef(verifier:Verifier, path:string) {
    verifier.router!.get(path, async (req: Request, response) => {
        debug("getting presentation definition", verifier.name, req.params);
        openObserverLog('none', 'get-presentation', { name: verifier.name, request: req.params});
        const presentation = verifier.getPresentation(req.params.presentationid);
        if (!presentation) {
            openObserverLog('none', 'get-presentation', { error: 'no presentation found'});
            return sendErrorResponse(response, 404, 'No such presentation for ' + req.params.presentationid);
        }
        openObserverLog('none', 'get-presentation', { name: verifier.name, response: presentation});
        debug("returning", presentation);
        return response.json(presentation);
    });
}
