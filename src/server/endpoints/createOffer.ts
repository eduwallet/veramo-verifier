import Debug from 'debug';
import { Request, Response } from 'express'
import { TokenErrorResponse } from '@sphereon/oid4vci-common'
import { sendErrorResponse } from '@sphereon/ssi-express-support'
import { GenerateAuthRequestURIResponse } from '@sphereon/ssi-sdk.siopv2-oid4vp-common'

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

export function createOffer(verifier: Verifier, createOfferPath: string, offerPath: string, responsePath:string, checkPath:string) {
    debug("creating route for createOffer at ", createOfferPath);
    verifier.router!.post(createOfferPath,
        passport.authenticate(verifier.name + '-admin', { session: false }),
        async (request: Request<CreateOfferRequest>, response: Response<CreateOfferResponse>) => {
        try {
            debug("received request to create a Verification Offer from ", verifier.name, request.body);
            const presentationId = request.params.presentationid;
            const state: string = v4();
            const requestByReferenceURI = getBaseUrl() + replaceParamsInUrl(offerPath, {presentationid: presentationId, state:state});
            const responseURI = getBaseUrl() + replaceParamsInUrl(responsePath, {presentationid: presentationId, state:state});

            if (!verifier.rp) {
                throw new Error("RP instance not configured");
            }
            else {
                var uri = await verifier.rp.createAuthorizationRequestURI({
                    correlationId: state,
                    nonce: v4(),
                    state: state,
                    requestByReferenceURI,
                    responseURI,
                    responseURIType: 'response_uri',
                    jwtIssuer: {
                        method: 'did',
                        didUrl: verifier.identifier!.did,
                        alg: verifier.signingAlgorithm()
                    }
                });

                const authRequestBody: CreateOfferResponse = {
                    state:state,
                    requestUri: uri.encodedUri,
                    checkUri: getBaseUrl() + replaceParamsInUrl(checkPath, { presentationid: presentationId, state:state }),
                }
                debug("returning ", authRequestBody);
                return response.send(authRequestBody)
            }
        } catch (e) {
            return sendErrorResponse(response, 500, 'Could not create authorization request', e);
        }
    });
}
  