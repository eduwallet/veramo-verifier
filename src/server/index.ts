import Debug from 'debug';
const debug = Debug(`verifier:server`)

import express from 'express';
import morgan from 'morgan'
import bodyParser from 'body-parser'
import cors from 'cors'

import { getVerifierStore } from 'verifier/VerifierStore';
import { bearerAdminForVerifier } from './bearerAdminForVerifier';
import { dumpExpressRoutes } from '@utils/dumpExpressRoutes';
import { createRoutesForVerifier } from './createRoutesForVerifier';
import { createRoutesForAdmin } from './admin/createRoutesForAdmin';

const PORT = process.env.PORT ? Number.parseInt(process.env.PORT) : 5000
const LISTEN_ADDRESS = process.env.LISTEN_ADDRESS ?? '0.0.0.0'
const BASEURL = process.env.BASEURL ?? 'https://verifier.dev.eduwallet.nl'

export async function initialiseServer() {
    const app = express();
    app.use(morgan('combined')); // use combined logging output
    app.use(express.urlencoded({ extended: true }));
    app.use(express.json({ limit: '50mb' }));
    app.use(cors({origin: '*', credentials: true, optionsSuccessStatus: 204}));

    // serving root page to accomodate ngrok
    app.get('/', (req, res) => {
        res.send(`<html><body><h1>Restricted Verifier API is running 🎉</h1></body></html>`);
    });

    createRoutesForAdmin(app);

    const store = getVerifierStore();
    debug('creating routes for each verifier instance', Object.keys(store));
    for (const verifier of Object.values(store)) {
        bearerAdminForVerifier(verifier);
        await createRoutesForVerifier(verifier, app);
    }

    debug("starting express server");
    app.listen(PORT, LISTEN_ADDRESS);
  
    dumpExpressRoutes(app);
}
