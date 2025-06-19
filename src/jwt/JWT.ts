import { fromString, toString } from 'uint8arrays';
import { Factory, CryptoKey } from '@muisit/cryptokey';
import { getEthereumAddressFromKey } from '@sphereon/ssi-sdk-ext.did-utils';

export class JWT {
    public token:string;
    public headerPart:string;
    public payloadPart:string|Uint8Array; // support non-string data for JWS signatures
    public signaturePart:string;
    public issuer:string;

    public header:any = null;
    public payload:any = null;


    constructor() {
        this.token = '';
        this.headerPart = '';
        this.payloadPart = '';
        this.signaturePart = '';
        this.issuer = '';
    }

    static fromToken(token:string)
    {
        let retval = new JWT();
        retval.token = token;
        const parts = token.match(/^([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)$/)
        if (parts && parts.length == 4) {
            retval.headerPart = parts[1];
            retval.payloadPart = parts[2];
            retval.signaturePart = parts[3];
            retval.decode();
        }

        if (!retval.header || !retval.payload || !retval.signaturePart
            || Object.keys(retval.header).length == 0 || Object.keys(retval.payload).length == 0
        ) {
            throw new Error("Invalid JWT");
        }

        return retval;
    }

    public decode()
    {
        if (this.headerPart.length > 0 && this.header === null) {
            this.header = this.decodeFromBase64(this.headerPart);
        }
        if (this.payloadPart.length > 0 && this.payload === null) {
            this.payload = this.decodeFromBase64(this.payloadPart);
        }
    }

    public async findKey()
    {
        let keyid = null;
        if (this.header && this.header.kid) {
            keyid = this.header.kid;
        }
        if (!keyid || keyid[0] === '#') {
            // relative key, look for an issuer
            if (this.header && this.header.iss) {
                // take the issuer key, append the key id if we have any
                keyid = this.header.iss + (keyid ? ('#' + keyid) : '');
            }
            else if (this.payload && this.payload.iss) {
                keyid = this.payload.iss + (keyid ? ('#' + keyid) : '');
            }
            else if (this.payload && this.payload.sub) {
                keyid = this.payload.sub + (keyid ? ('#' + keyid) : '');
            }
        }

        if (keyid) {
            // except for did:web, all did: methods only encode a single key, so we can drop the reference
            this.issuer = keyid.split('#')[0];
            return await Factory.resolve(this.issuer);
        }
        return null;
    }

    async verify(key:CryptoKey)
    {
        // verify the signature against the header+payload
        const data = Buffer.from(this.headerPart + '.' + this.payloadPart);
        const alg = this.header.alg || key.algorithms()[0];
        return await key.verify(alg, fromString(this.signaturePart, 'base64url'), data);
    }

    async sign(key:CryptoKey|Function, alg?:string)
    {
        const algUsed = alg || this.header.alg || 'ES256';
        if (typeof(key) != 'function') {
            this.header.alg = algUsed;
            this.header.kid = key.exportPublicKey();
        }
        if (this.header) {
            this.headerPart = this.encodeToBase64(this.header);
        }
        else if (!this.headerPart) {
            this.headerPart = '';
        }
        if (this.payload) {
            this.payloadPart = this.encodeToBase64(this.payload);
        }
        else if (!this.payloadPart) {
            this.payloadPart = '';
        }
        const data = Buffer.from(this.headerPart + '.' + this.payloadPart);
        if (typeof(key) != 'function') {
            this.signaturePart = await key.sign(algUsed, data, 'base64url');
        }
        else {
            this.signaturePart = await key(data);
        }
        this.token = this.headerPart + '.' + this.payloadPart + '.' + this.signaturePart;
    }

    public decodeFromBase64(payload:string)
    {
        let bytes = fromString(payload, 'base64url');
        let jsonstring = toString(bytes);
        try {
            return JSON.parse(jsonstring);
        }
        catch (e) {

        }
        return null;
    }

    public encodeToBase64(payload:any)
    {
        const encoded = Buffer.from(JSON.stringify(payload));
        return toString(encoded, 'base64url');
    }
}