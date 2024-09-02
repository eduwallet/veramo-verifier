import Debug from 'debug'
import express from 'express'
import { ExpressSupport } from "@sphereon/ssi-express-support";
import { Verifier } from "verifier/Verifier";
import { getBasePath } from '@utils/getBasePath';
import { getBaseUrl } from '@utils/getBaseUrl';
import { createOffer, getDidSpec, getOffer } from './endpoints';

const debug = Debug(`verifier:server`)

export async function createRoutesForVerifier(verifier:Verifier, expressSupport:ExpressSupport) {
    debug('creating routes for ', verifier.name);

    verifier.router = express.Router();
    expressSupport.express.use(getBasePath(getBaseUrl() + verifier.path), verifier.router);

    createOffer(
        verifier,
        '/api/create-offer/:presentationid',
        '/' + verifier.name + '/get-presentation/:presentationid/:state',
        '/' + verifier.name + '/response/:presentationid/:state',
        '/' + verifier.name + '/api/check-offer/:presentationid/:state'
    );

    getOffer(
        verifier,
        '/get-presentation/:presentationid/:state'
    );

    getDidSpec(verifier);
}

