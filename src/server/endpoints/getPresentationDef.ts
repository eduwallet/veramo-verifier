import { sendErrorResponse } from '@sphereon/ssi-express-support';
import { Request } from 'express'
import { Verifier } from 'verifier/Verifier';

export function getPresentationDef(verifier:Verifier, path:string) {
    verifier.router!.get(path, async (req: Request, response) => {
        const presentation = verifier.getPresentation(req.params.presentationid);
        if (!presentation) {
            return sendErrorResponse(response, 404, 'No such presentation for ' + req.params.presentationid);
        }
        return response.json(presentation);
    });
}
