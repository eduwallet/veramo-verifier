import { Factory } from "@muisit/cryptokey";
import { JWT } from "@muisit/simplejwt";
import { DCQLSubmission } from "verifier/DCQLSubmission";
import { timings } from "./timings";
import { sha256 } from '@noble/hashes/sha2'
import { toString } from "uint8arrays";

export async function KBJwt(submission:DCQLSubmission, token:string, sdjwt:JWT, hashableValue:string)
{

    // {
    //    "typ": "kb+jwt",
    //    "alg": "ES256"
    // }
    // {
    //    "iat": 1768398243,
    //    "nonce": "0a03f1c6-8d2f-43f5-8511-09aed1079d66",
    //    "aud": "decentralized_identifier:...",
    //    "sd_hash": "CGbRo_7Jgo8F4itBwSMDtpIdQmdw9dkJROqnhb_-nvE"
    // }
    let jwt;
    try {
        jwt = JWT.fromToken(token);
    }
    catch {
        submission.messages.push({code: 'INVALID_JWT', message: submission.credentialId + ': KB is not a valid JWT'}); 
        return;
    }

    let holder;
    if (sdjwt.payload?.cnf) {
        try {
            if (sdjwt.payload.cnf.kid) {
                // remove any trailing key identifier. This would only be required for did:web, but wallets should
                // not have did:web as holder key
                holder = await Factory.resolve(sdjwt.payload.cnf.kid.split('#')[0]);
            }
            else if(sdjwt.payload.cnf.jwk) {
                holder = await Factory.createFromJWK(sdjwt.payload.cnf.jwk);
            }
            else {
                submission.messages.push({code: 'INVALID_SDJWT', message: submission.credentialId + ': unsupported holder key type in SD-JWT'});
            }
        }
        catch {
            submission.messages.push({code: 'INVALID_SDJWT', message: submission.credentialId + ': holder key cannot be resolved'});
        }

        if (!holder) {
            submission.messages.push({code: 'INVALID_SDJWT', message: submission.credentialId + ': cannot determine holder key for SD-JWT to check KB signature'});
        }
        else {
            const isValidSignature = await jwt.verify(holder);
            if (!isValidSignature) {
                submission.messages.push({code: 'JWT_UNVERIFIED', message: submission.credentialId + ': could not validate signature of KB with holder key'});
            }
            else {
                submission.messages.push({code: 'JWT_VERIFIED', message: submission.credentialId + ': key binding was succesfully verified'});
            }
        }
    }

    if (!jwt.header?.typ || jwt.header.typ != 'kb+jwt') {
        submission.messages.push({code: 'INVALID_KB', message: submission.credentialId + ': invalid typ header'});
    }

    timings(submission, 'KB-JWT', jwt.payload?.nbf, jwt.payload?.iat, jwt.payload?.exp);

    // check that nonce and aud are correct
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0-28.html#appendix-B.3.6
    if (!jwt.payload?.aud || (jwt.payload.aud != submission.rp.verifier.clientId() && jwt.payload.aud != 'decentralized_identifier:' + submission.rp.verifier.clientId())) {
        submission.messages.push({code: 'INVALID_KB', message: submission.credentialId + ': aud claim does not match client id of verifier'});
    }
    if (!jwt.payload?.nonce || jwt.payload.nonce != submission.rp.session.data.nonce) {
        submission.messages.push({code: 'INVALID_KB', message: submission.credentialId + ': nonce claim does not match session nonce'});
    }

    const parts = hashableValue.split('~').slice(0, -1).join('~') + '~';
    const hashValue = toString(sha256(parts), 'base64url')
    if (!jwt.payload?.sd_hash) {
        submission.messages.push({code: 'INVALID_KB', message: submission.credentialId + ': missing hash over credential'});
    }
    else if (jwt.payload?.sd_hash != hashValue) {
        submission.messages.push({code: 'INVALID_KB', message: submission.credentialId + ': hash over credential does not match credential'});
    }    
}