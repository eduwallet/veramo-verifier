import Debug from 'debug';
import express from 'express';
import {ExpressBuilder, ExpressCorsConfigurer} from "@sphereon/ssi-express-support";
import { getVerifierStore } from 'verifier/VerifierStore';
import { bearerAdminForVerifier } from './bearerAdminForVerifier';
import { dumpExpressRoutes } from '@utils/dumpExpressRoutes';
import { createRoutesForVerifier } from './createRoutesForVerifier';
import bodyParser from 'body-parser';

const debug = Debug(`eduwallet:server`)

const PORT = process.env.PORT ? Number.parseInt(process.env.PORT) : 5000
const LISTEN_ADDRESS = process.env.LISTEN_ADDRESS ?? '0.0.0.0'
const BASEURL = process.env.BASEURL ?? 'https://verifier.dev.eduwallet.nl'

const expressSupport = ExpressBuilder.fromServerOpts({
    hostname: LISTEN_ADDRESS,
    port: PORT,
    basePath: new URL(BASEURL).toString()
})
    .withCorsConfigurer(new ExpressCorsConfigurer({}).allowOrigin('*').allowCredentials(true))
    .withMorganLogging({format:'combined'})
    .build({startListening: false});
// increase the request limit from 100kb or 1Mb to something that can include a modern image
expressSupport.express.use(bodyParser.json({limit: '50mb'}));
expressSupport.express.use(bodyParser.urlencoded({limit: '50mb', extended: true}));

export async function initialiseServer() {
    const store = getVerifierStore();
    debug('creating routes for each verifier instance', Object.keys(store));
    for (const verifier of Object.values(store)) {
        bearerAdminForVerifier(verifier);
        await createRoutesForVerifier(verifier, expressSupport);
    }

    debug("starting express server");
    expressSupport.start();

    dumpExpressRoutes(expressSupport.express);
}
