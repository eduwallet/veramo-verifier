import { getOIDFedInfo } from 'utils/getOIDFedInfo';
import { Request, Response } from 'express'
import { Verifier } from 'verifier/Verifier';

export function getOIDFed(verifier: Verifier) {
    const path = '/.well-known/openid-federation';

    verifier.router!.get(path, async (request: Request, response: Response) => {
        return response.send(await getOIDFedInfo(verifier));
    });
}
