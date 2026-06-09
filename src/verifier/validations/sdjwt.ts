import { DCQLSubmission } from "../DCQLSubmission";
import { JWT } from "@muisit/simplejwt";
import { timings } from "./timings";
import { findKeyOfJwt } from "@utils/findKeyOfJwt";
import { KBJwt } from "./kbjwt";

export async function sdjwt(submission:DCQLSubmission)
{
    let tokens = submission.presentation as string[];
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#appendix-B.3.6
    // presentationresult should be an array of string tokens
    if (!Array.isArray(tokens)) {
        submission.messages.push({code: 'INVALID_PRESENTATION', message: submission.credentialId + ': dc+sd-jwt expects array of JWT tokens'});
        tokens = [tokens];
    }

    // tokens is a list of SD-JWT with KB jwts
    for (const token of tokens) {
        if (typeof token !== 'string') {
            submission.messages.push({code: 'INVALID_PRESENTATION', message: submission.credentialId + ': dc+sd-jwt expects string SD-JWT tokens'});
        }
        else {
            // extract the final JWT from the SD-JWT
            const parts = token.split('~');
            // the first part is the SD-JWT, the last part can be a KB-JWT
            let sdjwt;
            try {
                sdjwt = JWT.fromToken(parts[0]);
            }
            catch {
                submission.messages.push({code: 'INVALID_PRESENTATION', message: submission.credentialId + ': cannot decode SD-JWT'});
                return;
            }

            // if the last entry of the split is empty, it means there is no KB-JWT
            if (parts[parts.length - 1].length == 0) {
                submission.messages.push({code: 'MISSING_KB', message: submission.credentialId + ': dc+sd-jwt token does not have a key-binding JWT attached'});
            }
            else {
                await KBJwt(submission, parts[parts.length - 1], sdjwt, token);
            }

            // validate the SD-JWT
            // the sdjwt.findKey() implementation is the same as in this class, but it resolved to null for some reason...
            const key = await findKeyOfJwt(sdjwt);
            if (!key) {
                submission.messages.push({code: 'INVALID_PRESENTATION', message: submission.credentialId + ': could not determine signing key of SD-JWT'});
            }
            else {
                const validatedJwt = await sdjwt.verify(key);
                if (!validatedJwt) {
                    submission.messages.push({code: 'INVALID_PRESENTATION', message: submission.credentialId + ': could not verify signature of SD-JWT'});
                }
            }

            timings(submission, 'SD-JWT', sdjwt.payload?.nbf, sdjwt.payload?.iat, sdjwt.payload?.exp);

            // then extract all hashes and provide them as attributes/claims
            await submission.extractSDJwtCredential(sdjwt, token);
        }
    }
}

