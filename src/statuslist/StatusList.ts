import { verifyJWT } from 'externals';
import { resolver } from 'agent';
import moment from 'moment';
import {Bitstring} from '@digitalcredentials/bitstring';
import { Message } from 'types';

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
        const jwt = await fetch(statusList).then((r) => r.text()).catch((e) => {
            throw new Error('STATUSLIST_UNREACHABLE:Statuslist could not be retrieved');
        });
        var verifiedJwt = null;
        if (jwt) {
            try {
                verifiedJwt = await verifyJWT(jwt, { resolver: resolver });
                if (!verifiedJwt) {
                    throw new Error("no JWT found");
                }
            }
            catch (e:any) {
                throw new Error('STATUSLIST_INVALID:Statuslist did not properly decode from JWT');
            }
        }
        if (verifiedJwt) {
            if (verifiedJwt.payload.credentialSubject && verifiedJwt.payload.credentialSubject.encodedList) {
                this.cachedLists[statusList] = {
                    id: verifiedJwt.payload.credentialSubject.encodedList,
                    purpose: verifiedJwt.payload.credentialSubject.statusPurpose ?? 'revocation',
                    retrieved: new Date(),
                    expires: moment().add(60 * 60, 's').toDate()
                }
                return;
            }
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
