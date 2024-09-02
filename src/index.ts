import { createVerifiers } from 'verifier/VerifierStore';
import { initialiseServer } from './server';
import { createDids } from 'utils/createDids';

async function main() {
    await createDids();
    await createVerifiers();
    await initialiseServer();
}

main().catch(console.log)

