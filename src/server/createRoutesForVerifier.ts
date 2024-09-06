import Debug from 'debug'
import express from 'express'
import { ExpressSupport } from "@sphereon/ssi-express-support";
import { Verifier } from "verifier/Verifier";
import { getBasePath } from '@utils/getBasePath';
import { getBaseUrl } from '@utils/getBaseUrl';
import { checkOffer, createOffer, getDidSpec, getOffer, getPresentationDef, receiveResponse } from './endpoints';

const debug = Debug(`verifier:server`)

const create_offer_path = '/api/create-offer/:presentationid';
const get_offer_path = '/get-offer/:state';
const get_presentation_path = '/get-presentation/:presentationid';
const response_path = '/response/:state';
const check_offer_path = '/api/check-offer/:state';

export async function createRoutesForVerifier(verifier:Verifier, expressSupport:ExpressSupport) {
    debug('creating routes for ', verifier.name);

    verifier.router = express.Router();
    expressSupport.express.use(getBasePath(getBaseUrl() + verifier.path), verifier.router);

    createOffer(
        verifier,
        create_offer_path,
        '/' + verifier.name + get_offer_path,
        '/' + verifier.name + response_path,
        '/' + verifier.name + get_presentation_path,
        '/' + verifier.name + check_offer_path
    );

    getOffer(verifier, get_offer_path);
    receiveResponse(verifier, response_path);
    checkOffer(verifier, check_offer_path);
    getDidSpec(verifier);
    getPresentationDef(verifier, get_presentation_path);
}

