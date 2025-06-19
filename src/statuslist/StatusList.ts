import { verifyJWT } from 'externals';
import { resolver } from 'agent';
import moment from 'moment';
import {Bitstring} from '@digitalcredentials/bitstring';
import { Message } from 'types';
import { JWT } from 'jwt/JWT';

interface CachedList {
    id: string;
    purpose: string;
    retrieved: Date;
    expires: Date;
}

interface CachedLists {
    [x:string]: CachedList;
}

export class StatusList
{
    private cachedLists:CachedLists = {}

    private statusListIsAvailable(statusList:string)
    {
        if (!this.cachedLists[statusList]) {
            return false;
        }
        const now = new Date();
        if (this.cachedLists[statusList].expires < now) {
            return false;
        }
        return true;
    }

    private async retrieveList(statusList:string)
    {
        const token = await fetch(statusList).then((r) => r.text()).catch((e) => {
            throw new Error('STATUSLIST_UNREACHABLE:Statuslist could not be retrieved');
        });
        const jwt = JWT.fromToken(token);
        const key = await jwt.findKey();
        if (!key) {
            throw new Error("STATUSLIST_INVALID:Status list does not contain a key");
        }
        if (!await jwt.verify(key)) {
            throw new Error("STATUSLIST_INVALID:Status list JWT cannot be verified");
        }

        if (jwt.payload.credentialSubject && jwt.payload.credentialSubject.encodedList) {
            this.cachedLists[statusList] = {
                id: jwt.payload.credentialSubject.encodedList,
                purpose: jwt.payload.credentialSubject.statusPurpose ?? 'revocation',
                retrieved: new Date(),
                expires: moment().add(60 * 60, 's').toDate()
            }
            return;
        }
        if (jwt.payload.vc?.credentialSubject && jwt.payload.vc?.credentialSubject.encodedList) {
            this.cachedLists[statusList] = {
                id: jwt.payload.vc!.credentialSubject.encodedList,
                purpose: jwt.payload.vc!.credentialSubject.statusPurpose ?? 'revocation',
                retrieved: new Date(),
                expires: moment().add(60 * 60, 's').toDate()
            }
            return;
        }
        throw new Error('STATUSLIST_INVALID:Statuslist does not contain an encodedList claim');
    }

    private async getStatusList(statusList:string): Promise<CachedList>
    {
        if (!this.statusListIsAvailable(statusList)) {
            await this.retrieveList(statusList);
        }
        return this.cachedLists[statusList];
    }

    public async checkStatus(statusList:string, index:number): Promise<Message>
    {
        const retval:Message = { code: '', message: ''};
        var list:CachedList|null = null;
        
        try {
            list = await this.getStatusList(statusList);
        }
        catch (e:any) {
            const errorElements = e.message.split(':');
            retval.code = errorElements[0];
            retval.message = errorElements[1] ?? '';
            return retval;
        }

        const encoded = list!.id;
        const dataList = new Bitstring({buffer:await Bitstring.decodeBits({encoded})});
        if (dataList.get(index)) {
            if (list!.purpose == 'revocation') {
                retval.code = 'CREDENTIAL_REVOKED';
                retval.message = 'Statuslist indicates credential was revoked';
            }
            else if (list!.purpose == 'suspension') {
                retval.code = 'CREDENTIAL_SUSPENDED';
                retval.message = 'Statuslist indicates credential was suspended';
            }
            else {
                retval.code = 'CREDENTIAL_STATUS_SET';
                retval.message = 'Statuslist purpose is unknown, but credential was set as ' + (list!.purpose || 'unknown_purpose');
            }
        }
        else {
            // give feedback that we actually tested this credential against an external statuslist
            retval.code = 'CREDENTIAL_STATUS_OK';
            retval.message = 'Credential is not set in statuslist with purpose ' + (list!.purpose || 'unknown_purpose');
        }
        return retval;
    }
}
