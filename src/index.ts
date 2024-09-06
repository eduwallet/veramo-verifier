import { createVerifiers } from 'verifier/VerifierStore';
import { initialiseServer } from './server';
import { createDids } from 'utils/createDids';
import { initialisePresentationStore } from 'presentations/PresentationStore';

async function main() {
    await createDids();
    await createVerifiers();
    await initialisePresentationStore();
    await initialiseServer();
}

main().catch(console.log)

