import moment from "moment";
import { DCQLSubmission } from "verifier/DCQLSubmission";

export function timings(submission:DCQLSubmission, format: string, nbf?:number, iat?:number, exp?:number)
{
    const now:number = Math.floor(Date.now() / 1000);

    if (nbf && nbf > now) {
        const _nbf = moment(nbf * 1000).toISOString();
        submission.messages.push({code: 'NBF_ERROR', message: submission.credentialId + ': ' + format + ` is not valid before ${_nbf}`, _nbf});
    }
    if (iat && iat > now) {
        const _iat = moment(iat * 1000).toISOString();
        submission.messages.push({code: 'IAT_ERROR', message: submission.credentialId + ': ' + format + ` is issued in the future at ${_iat}`, _iat});
    }
    if (exp && exp <= now) {
        const _exp = moment(exp * 1000).toISOString();
        submission.messages.push({code: 'EXP_ERROR', message: submission.credentialId + ': ' + format + ` expired at ${_exp}`, _exp});
    }
}