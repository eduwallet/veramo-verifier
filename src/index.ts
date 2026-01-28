import Debug from 'debug';
const debug = Debug('verifier:main');

import { createVerifiers } from 'verifier/VerifierStore';
import { initialiseServer } from './server';
import { initialisePresentationStore } from 'presentations/PresentationStore';
import { getDIDConfigurationStore } from 'dids/Store';
import { getDb } from 'database';

async function main() {
    debug("Initialising database");
    const db = getDb();
    await db.initialise();

    debug('Loading and/or creating keys and identifiers');
    const didStore = getDIDConfigurationStore();
    await didStore.init();

    await createVerifiers();
    await initialisePresentationStore();
    await initialiseServer();
}

main().catch(console.log)

