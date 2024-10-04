import { sendErrorResponse } from '@sphereon/ssi-express-support';
import { openObserverLog } from '@utils/openObserverLog';
import { Request } from 'express'
import { Verifier } from 'verifier/Verifier';

export function getPresentationDef(verifier:Verifier, path:string) {
    verifier.router!.get(path, async (req: Request, response) => {
        openObserverLog('none', 'get-presentation', { name: verifier.name, request: req.params});
        const presentation = verifier.getPresentation(req.params.presentationid);
        if (!presentation) {
            openObserverLog('none', 'get-presentation', { error: 'no presentation found'});
            return sendErrorResponse(response, 404, 'No such presentation for ' + req.params.presentationid);
        }
        openObserverLog('none', 'get-presentation', { name: verifier.name, response: presentation});
        return response.json(presentation);
    });
}
