import Debug from 'debug';
import { Request, Response } from 'express'
import { sendErrorResponse } from '../sendErrorResponse';
import { Verifier } from 'verifier/Verifier';
import passport from 'passport';
import { v4 } from 'uuid';
import { replaceParamsInUrl } from '@utils/replaceParamsInUrl';
import { getBaseUrl } from '@utils/getBaseUrl';

const debug = Debug("verifier:createOffer");
interface CreateOfferRequest {
    [x:string]: any;
}

interface CreateOfferResponse {
    state: string;
    checkUri: string;
    requestUri: string;
}

export function createOffer(verifier: Verifier, createOfferPath: string, offerPath: string, responsePath:string, presentationPath:string, checkPath:string) {
    debug("creating route for createOffer at ", createOfferPath);
    verifier.router!.post(createOfferPath,
        passport.authenticate(verifier.name + '-admin', { session: false }),
        async (request: Request<CreateOfferRequest>, response: Response<CreateOfferResponse>) => {
        try {
            debug("received request to create a Verification Offer from ", verifier.name, request.body);
            const session = await verifier.sessionManager.get('');
            const presentationId = request.params.presentationid;
            const requestByReferenceURI = getBaseUrl() + replaceParamsInUrl(offerPath, {presentationid: presentationId, state:session.id});
            const checkUri = getBaseUrl() + replaceParamsInUrl(checkPath, { presentationid: presentationId, state:session.id });
            // https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html#section-9
            // "when using request_uri, the only other required parameter ... is client_id"
            const requestUri = 'openid://?request_uri=' + encodeURIComponent(requestByReferenceURI) + '&client_id=' + encodeURIComponent(verifier.clientId());

            const rp = await verifier.getRPForPresentation(presentationId);
            if (!rp) {
                throw new Error("RP instance not configured");
            }
            else {
                rp.state = session.id;
                rp.createAuthorizationRequest();
                session.data.rp = rp;
                await verifier.sessionManager.set(session);
                const authRequestBody: CreateOfferResponse = {state:rp.state, requestUri, checkUri};
                debug("returning ", authRequestBody);
                return response.send(authRequestBody)
            }
        } catch (e) {
            return sendErrorResponse(response, 500, 'Could not create authorization request', e);
        }
    });
}
  