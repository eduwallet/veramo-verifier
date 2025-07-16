import { Message } from "types";
import { ExtractedCredential } from "./DCQLSubmission";
import { RP } from "./RP";

export async function validateStatusLists(rp:RP, credential:ExtractedCredential)
{
    const messages:Message[] = [];
    if (credential.metadata?.statusLists && credential.metadata?.statusLists.length) {
        for (const statusList of credential.metadata?.statusLists) {
            const { code, value, message } = await rp.verifier.statusList.check(statusList);
            switch (code ?? 'UNRESOLVED') {
                default:
                    messages.push({code: 'STATUS_LIST_INVALID', message: code + ':' + message, value});
                    break;
                case 'CREDENTIAL_OK':
                    messages.push({code:'STATUS_LIST_VALID', message, value});
                    break;
                case 'CREDENTIAL_REVOKED':
                    messages.push({code:'STATUS_LIST_REVOKED', message, value});
                    break;
                case 'CREDENTIAL_SUSPENDED':
                    messages.push({code:'STATUS_LIST_SUSPENDED', message, value});
                    break;
                case 'CREDENTIAL_SET':
                    messages.push({code:'STATUS_LIST_MESSAGE', message:message, value});
                    break;
            }
        }
    }
    else {
        messages.push({code:'NO_STATUS_LIST', message:'credential does not implement a status list'});
    }
    return messages;
}