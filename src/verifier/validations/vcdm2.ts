import { DCQLSubmission } from "../DCQLSubmission";
import { JWT } from "@muisit/simplejwt";
import { timings } from "./timings";

export async function VCDM2(submission:DCQLSubmission)
{
    let tokens = submission.presentation as string[];
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#appendix-B.1.3.1.5
    // presentationresult should be an array of string tokens
    if (!Array.isArray(tokens)) {
        submission.messages.push({code: 'INVALID_PRESENTATION', message: submission.credentialId + ': vc+jwt expects array of JWT tokens'});
        tokens = [tokens];
    }

    for (const token of tokens) {
        if (typeof token !== 'string') {
            submission.messages.push({code: 'INVALID_PRESENTATION', message: submission.credentialId + ': vc+jwt expects string JWT tokens'});
        }
        else {
            const jwt = JWT.fromToken(token);

            if (!jwt.payload?.aud || jwt.payload.aud != submission.rp.verifier.clientId()) {
                submission.messages.push({code: 'INVALID_PRESENTATION', message: submission.credentialId + ': aud claim does not match client id of verifier'});
            }
            if (!jwt.payload?.nonce || jwt.payload.nonce != submission.rp.session.data.nonce) {
                submission.messages.push({code: 'INVALID_PRESENTATION', message: submission.credentialId + ': nonce claim does not match session nonce'});
            }

            timings(submission, 'VCDM2', jwt.payload?.nbf, jwt.payload?.iat, jwt.payload?.exp);

            await submission.extractVCDMCredentials(jwt.payload);
        }
    }
}