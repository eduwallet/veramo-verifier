import Debug from 'debug'
import express, {Express} from 'express'
import { Verifier } from "verifier/Verifier";
import { getBasePath } from '@utils/getBasePath';
import { getBaseUrl } from '@utils/getBaseUrl';
import { checkOffer, checkStatus, createOffer, getDidSpec, getOffer, getPresentationDef, receiveResponse } from './endpoints';
import { createDcqlOffer } from './endpoints/createDcqlOffer';

const debug = Debug(`verifier:server`)

const create_offer_path = '/api/create-offer/:presentationid';
const create_dcql_offer_path = '/api/create-dcql-offer';
const get_offer_path = '/get-offer/:state';
export const get_presentation_path = '/get-presentation/:presentationid';
export const response_path = '/response/:state';
const check_offer_path = '/api/check-offer/:state';
const check_status_path = '/api/check-status';

export async function createRoutesForVerifier(verifier:Verifier, app:Express) {
    debug('creating routes for ', verifier.name);

    verifier.router = express.Router();
    app.use(getBasePath(getBaseUrl() + verifier.path), verifier.router);

    createOffer(
        verifier,
        create_offer_path,
        '/' + verifier.name + get_offer_path,
        '/' + verifier.name + response_path,
        '/' + verifier.name + get_presentation_path,
        '/' + verifier.name + check_offer_path
    );

    createDcqlOffer(
        verifier,
        create_dcql_offer_path,
        '/' + verifier.name + get_offer_path,
        '/' + verifier.name + response_path,
        '/' + verifier.name + check_offer_path
    );

    getOffer(verifier, get_offer_path);
    receiveResponse(verifier, response_path);
    checkOffer(verifier, check_offer_path);
    checkStatus(verifier, check_status_path);
    getDidSpec(verifier);
    getPresentationDef(verifier, get_presentation_path);
}

