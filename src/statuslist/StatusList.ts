import moment from 'moment';
import {Bitstring} from '@digitalcredentials/bitstring';
import { JWT } from '@muisit/simplejwt';
import { ungzip } from 'pako';
import { inflateSync } from 'zlib';
import { fromString } from 'uint8arrays';
import { findKeyOfJwt } from '../utils/findKeyOfJwt';

interface CachedList {
    id: string;
    url: string;
    type: string;
    purpose: string;
    retrieved: Date;
    expires: Date;
    data?: Bitstring;
    size:number;
}

interface CachedLists {
    [x:string]: CachedList;
}

interface StatusMessage {
    status:string;
    message:string;
}

interface StatusCheckResult {
    value: number;
    code: string;
    message: string;
}

export interface StatusListEntry {
    type?:string;
    idx?:number;
    uri?:string;
    [x:string]: any;
}

export class StatusList
{
    private cachedLists:CachedLists = {}

    public async check(statusListEntry:StatusListEntry): Promise<StatusCheckResult>
    {
        let url:string;
        let index:number;
        let type:string;
        let purpose:string = 'unknown';
        let size:number = 1;
        let messages:any = null;
        // if there is no type entry, assume it is an ietf status list
        switch (statusListEntry.type ?? 'status+jwt') {
            default:
            case 'BitstringStatusListEntry':
                url = statusListEntry.statusListCredential;
                index = statusListEntry.statusListIndex;
                size = parseInt(statusListEntry.statusSize || '1');
                messages = statusListEntry.statusMessage || null;
                type = 'bitstring';
                purpose = 'unknown';
                break;
            case 'StatusListStatus':
                url = statusListEntry.statusListCredential;
                index = statusListEntry.statusListIndex;
                size = 1;
                type = 'statuslist';
                purpose = 'unknown';
                break;
            case 'RevocationList2020Status':
            case 'RevocationList2021Status':
                url = statusListEntry.statusListCredential;
                index = statusListEntry.statusListIndex;
                size = 1;
                type = 'statuslist';
                purpose = 'revocation';
                break;
            case 'SuspensionList2020Status':
            case 'SuspensionList2021Status':
                url = statusListEntry.statusListCredential;
                index = statusListEntry.statusListIndex;
                size = 1;
                type = 'statuslist';
                purpose = 'suspension';
                break;
            case 'status+jwt':
                url = statusListEntry.uri ?? '';
                index = statusListEntry.idx ?? 0;
                // size is set on the status list output
                type = 'ietf';
                break;
        }
        // this allows us to generically re-check a statuslist by providing type, url, index and size
        if (!url && statusListEntry.url) {
            url = statusListEntry.url;
        }

        var list:CachedList|null = null;
        
        try {
            list = await this.getStatusList(url, type, purpose, size);
        }
        catch (e:any) {
            const errorElements = e.message.split(':');
            return {
                value: -1,
                code: errorElements[0],
                message: errorElements[1]
            };
        }

        if (messages == null) {
            messages = this.createMessages(list.size, list.purpose);
        }
        return await this.determineMessage(list, index, list.size, messages);
    }

    private async determineMessage(list:StatusListEntry, index:number, size:number, messages:StatusMessage[])
    {
        const encoded = list!.data;
        const dataList = new Bitstring({buffer:await Bitstring.decodeBits({encoded})});
        const value = this.getStateValue(dataList, index, size);
        let message:StatusMessage|null = null;
        for (const msg of messages) {
            if (parseInt(msg.status) === value) {
                message = msg;
                break;
            }
        }

        if (message == null) {
            // should not occur, unless we have missing messages in the Bitstring entry
            throw new Error(`STATUSLIST_INVALID:No message for value ${value}`);
        }

        let retval:StatusCheckResult = {
            value: value,
            code: 'CREDENTIAL_OK',
            message: message.message
        };

        if (message.message == 'revoked') {
            retval.code = 'CREDENTIAL_REVOKED';
        }
        else if (message.message == 'suspended') {
            retval.code = 'CREDENTIAL_SUSPENDED';
        }
        else if (value > 0) {
            retval.code = 'CREDENTIAL_STATUS_SET';
        }
        else {
            retval.message = 'Credential is not set in statuslist with purpose ' + list.purpose;
        }
        return retval;
    }

    private getStateValue(bitString:Bitstring, index:number, bitSize:number)
    {
        let retval:number = 0;
        for(let i = 0;i < bitSize; i++) {
            const bitval = bitString.get((index * bitSize) + i);
            retval = (retval << 1) | (bitval ? 1 : 0);
        }
        return retval;
    }

    // create a list of default status messages according to the BitstringStatusList spec
    private createMessages(size:number, purpose:string): StatusMessage[]
    {
        if (size === 1) {
            return [{
                "status": "0x0",
                "message": purpose == 'revocation' ? 'unrevoked' : (purpose == 'suspension' ? 'unsuspended' : 'unset')
            },{
                "status": "0x1",
                "message": purpose == 'revocation' ? 'revoked' : (purpose == 'suspension' ? 'suspended' : 'set')
            }]
        }
        else {
            let retval:StatusMessage[] = [];
            for (let i = 0; i <= (1 << size); i++) {
                retval.push({
                    status: "0x" + i.toString(16),
                    message: i.toString()
                });
            }
            return retval;
        }
    }

    private async getStatusList(statusList:string, type:string, purpose:string, size:number): Promise<CachedList>
    {
        if (!this.statusListIsAvailable(statusList)) {
            await this.retrieveList(statusList, type, purpose, size);
        }
        return this.cachedLists[statusList];
    }

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

    private async retrieveList(statusList:string, type:string, purpose:string, size:number)
    {
        const token = await fetch(statusList).then((r) => r.text()).catch((e) => {
            throw new Error('STATUSLIST_UNREACHABLE:Statuslist could not be retrieved');
        });
        let jwt:JWT;
        try {
            jwt = JWT.fromToken(token);
        }
        catch (e:any) {
            throw new Error('STATUSLIST_INVALID:Statuslist did not properly decode from JWT');
        }

        const ckey = await findKeyOfJwt(jwt);
        if (!ckey) {
            throw new Error('STATUSLIST_INVALID:Statuslist could not be verified');
        }
        if (!jwt.verify(ckey)) {
            throw new Error('STATUSLIST_INVALID:Statuslist could not be verified');
        }
        if (!jwt.payload) {
            throw new Error('STATUSLIST_INVALID:Statuslist has no content');
        }

        let entry:CachedList = {
            id: '',
            url: '',
            purpose: purpose,
            type: type,
            retrieved: new Date(),
            expires: moment().add(60 * 60, 's').toDate(),
            size: size
        };
        switch (type) {
            case 'ietf':
                if (jwt.payload!.status_list && jwt.payload!.status_list.bits && jwt.payload!.status_list.lst) {
                    entry.id = statusList;
                    entry.url = statusList;
                    entry.size = jwt.payload!.status_list.bits;
                    entry.data = await this.toBitstring(await this.decodeIETF(jwt.payload.status_list.lst));
                }
                else {
                    throw new Error(`STATUSLIST_INVALID:Missing fields in IETF Status Token List`);
                }
                break;
            case 'bitstring':
                if (jwt.payload!.credentialSubject && jwt.payload!.credentialSubject.statusPurpose && jwt.payload!.credentialSubject.encodedList) {
                    entry.id = statusList;
                    entry.url = statusList;
                    if (entry.purpose == 'unknown') {
                        entry.purpose = jwt.payload.credentialSubject.statusPurpose;
                    }
                    entry.data = await this.toBitstring(await this.decodeBitstring(jwt.payload.credentialSubject.encodedList));
                }
                else {
                    throw new Error(`STATUSLIST_INVALID:Missing fields in BitstringStatusList`);
                }
                break;
            case 'statuslist':
                if (jwt.payload!.credentialSubject && jwt.payload!.credentialSubject.encodedList) {
                    entry.id = statusList;
                    entry.url = statusList;
                    if (entry.purpose == 'unknown') {
                        entry.purpose = jwt.payload.credentialSubject.statusPurpose;
                    }
                    entry.data = await this.toBitstring(await this.decodeStatuslist(jwt.payload.credentialSubject.encodedList));
                }
                else {
                    throw new Error(`STATUSLIST_INVALID:Missing fields in StatusList2020/StatusList2021`);
                }
                break;
            default:
                throw new Error(`STATUSLIST_INVALID:Unsupported internal type ${type}`);
        }

        this.cachedLists[statusList] = entry;
    }

    private async toBitstring(data:Uint8Array)
    {
        const lst = new Bitstring({buffer: data});
        return lst.encodeBits();
    }

    private async decodeIETF(token:string)
    {
        // IETF has a zlib encoded base64url encoded bitstring
        return inflateSync(fromString(token, 'base64url'));
    }

    private async decodeBitstring(token:string)
    {
        // bitstring has a multibase encoded GZIPped bitstring
        const encoding = token[0];
        if (encoding === 'u') {
            return ungzip(fromString(token.substring(1), 'base64url'));
        }
        else if(encoding == 'z') {
            return ungzip(fromString(token.substring(1), 'base58btc'));
        }
        throw new Error("STATUSLIST_INVALID:Unsupported multibase encoding");
    }

    private async decodeStatuslist(token:string)
    {
        // ye ol' statuslist has a regular gzip encoded base64 url
        return ungzip(fromString(token, 'base64url'));
    }
}
