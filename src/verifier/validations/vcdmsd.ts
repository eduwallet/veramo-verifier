import { DCQLSubmission } from "../DCQLSubmission";
import { JWT } from "@muisit/simplejwt";
import { timings } from "./timings";
import { findKeyOfJwt } from "@utils/findKeyOfJwt";

export async function VCDM2SD(submission:DCQLSubmission)
{
    let tokens = submission.presentation as string[];
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#appendix-B.1.3.1.5
    // presentationresult should be an array of string tokens
    if (!Array.isArray(tokens)) {
        submission.messages.push({code: 'INVALID_PRESENTATION', message: submission.credentialId + ': vc+sd-jwt expects array of JWT tokens'});
        tokens = [tokens];
    }

    for (const token of tokens) {
        if (typeof token !== 'string') {
            submission.messages.push({code: 'INVALID_PRESENTATION', message: submission.credentialId + ': vc+sd-jwt expects string JWT tokens'});
        }
        else {
            const parts = token.split('~');
            if (parts.length < 2) {
                submission.messages.push({code: 'INVALID_PRESENTATION', message: submission.credentialId + ': vc+sd-jwt expects an SD-JWT token'});
            }
            const sdjwt = JWT.fromToken(parts[0]);

            if (!sdjwt.payload?.aud || sdjwt.payload.aud != submission.rp.verifier.clientId()) {
                submission.messages.push({code: 'INVALID_PRESENTATION', message: submission.credentialId + ': aud claim does not match client id of verifier'});
            }
            if (!sdjwt.payload?.nonce || sdjwt.payload.nonce != submission.rp.session.data.nonce) {
                submission.messages.push({code: 'INVALID_PRESENTATION', message: submission.credentialId + ': nonce claim does not match session nonce'});
            }

            timings(submission, 'vc+sd-jwt', sdjwt.payload?.nbf, sdjwt.payload?.iat, sdjwt.payload?.exp);

            const key = await findKeyOfJwt(sdjwt);
            if (!key) {
                submission.messages.push({code: 'INVALID_SDJWT', message: submission.credentialId + ': could not determine signing key of vc+sd-jwt'});
            }
            else {
                const validatedJwt = await sdjwt.verify(key);
                if (!validatedJwt) {
                    submission.messages.push({code: 'INVALID_SDJWT', message: submission.credentialId + ': could not verify signature of vc+sd-jwt'});
                }
                else {
                    await submission.extractSDJwtCredential(sdjwt, token);
                }
            }
        }
    }
}