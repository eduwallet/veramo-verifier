import { createVerifiers } from 'verifier/VerifierStore';
import { initialiseServer } from './server';

async function main() {
    await createVerifiers();
    await initialiseServer();
}

main().catch(console.log)

