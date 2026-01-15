import { Message } from 'types';
import moment from 'moment';
import { RP } from './RP';
import { JWT } from '@muisit/simplejwt';
import { ExtractedCredential } from './DCQLSubmission';
import { fromString } from 'uint8arrays';
import { validateStatusLists } from './validateStatusLists';
import { CryptoKey } from '@muisit/cryptokey/*';

export interface MetaData {
    [x:string]: any;
}

export class PresentationSubmission
{
    public rp:RP;
    public token:string;
    public id:string = 'unknown';
    public format:string = '';
    public credentials:ExtractedCredential[];
    public messages:Message[];

    public constructor(rp:RP, token:string)
    {
        this.rp = rp;
        this.token = token;
        this.credentials = [];
        this.messages = [];
    }

    public async validate()
    {
        await this.parseCredentialToken(this.token);
    }

    private async parseCredentialToken(token:string, holder?:string)
    {
        // this should be a VC, but Sphereon hands out a VP instead... old specs
        // See if this may be a JWT
        let payload:any;
        try {
            // take care of SD-JWTs
            const elements = token.split('~');
            const jwt = JWT.fromToken(elements[0]);
            payload = jwt.payload;

            let ckey:CryptoKey|null = null;
            try {
                ckey = await jwt.findKey();
            }
            catch (e) {
                ckey = null;
            }
            if (!ckey) {
                this.messages.push({
                    code: 'JWT_UNVERIFIED',
                    message: 'Could not determine signing key of credential JWT',
                    payload: token
                });
            }
            else if(!await jwt.verify(ckey)) {
                this.messages.push({
                    code: 'JWT_UNVERIFIED',
                    message: 'Could not verify signature of credential JWT',
                    payload: token
                });
            }
            else {
                this.messages.push({
                    code: 'JWT_VERIFIED',
                    message: 'Credential JWT verified'
                });
            }
        }
        catch (e) {
            // not a JWT, maybe just base64url encoded JSON
            try {
                payload = JSON.parse(fromString(token, 'base64url'));
            }
            catch (e) {
                this.messages.push({
                    code: 'INVALID_JWT',
                    message: 'Could not decode presentation response',
                    payload: token
                });
                return;
            }
        }

        // TODO: implement json-ld signatures
    
        // if this is a VP, it has a type of VerifiablePresentation
        if (payload.type && Array.isArray(payload.type) && payload.type.includes('VerifiablePresentation')) {
            await this.parseVP(payload);
        }
        else if (payload.vc && payload.vc.type && Array.isArray(payload.vc.type) && payload.vc.type.includes('VerifiableCredential')) {
            // a VCDM 1.1 credential
            this.id = payload.vc.type.filter((v:string) => v != 'VerifiableCredential')[0];
            this.format = 'jwt_vc_json';
            await this.parseVCDMCredential(payload.vc, holder);
        }
        else if (payload.type && Array.isArray(payload.type) && payload.type.includes('VerifiableCredential')) {
            this.id = payload.type.filter((v:string) => v != 'VerifiableCredential')[0];
            this.format = 'vc+jwt';
            await this.parseVCDMCredential(payload, holder);
        }
        else if (payload.vct && token.indexOf('~') > 0) {
            // an SD-JWT
            this.id = payload.vct;
            this.format = 'dc+sd-jwt';
            await this.parseSDCredential(payload, token, holder);
        }
        else {
            this.messages.push({
                code: 'UNSUPPORTED_VC',
                message: 'Decoded response token could not be interpreted',
                payload: payload
            });
        }
    }

    private async parseVP(payload:any)
    {
        if (!payload?.aud || payload.aud != this.rp.verifier.clientId()) {
            this.messages.push({code: 'INVALID_PRESENTATION', message: 'aud claim does not match client id of verifier', aud:payload.aud, clientId: this.rp.verifier.clientId()});
        }
        if (!payload?.nonce || payload.nonce != this.rp.nonce) {
            this.messages.push({code: 'INVALID_PRESENTATION', message: 'nonce claim does not match session nonce', nonce:payload.nonce, expected:this.rp.nonce});
        }

        const now:number = Math.floor(Date.now() / 1000);

        if (payload?.nbf && payload.nbf > now) {
            const nbf = moment(payload.nbf * 1000).toISOString();
            this.messages.push({code: 'NBF_ERROR', message: `VC is not valid before ${nbf}`, nbf: payload.nbf, now});
        }
        if (payload?.iat && payload.iat > now) {
            const iat = moment(payload.iat * 1000).toISOString();
            this.messages.push({code: 'IAT_ERROR', message: `VC is issued in the future at ${iat}`, iat: payload.iat, now});
        }
        if (payload?.exp && payload.exp <= now) {
            const exp = moment(payload.exp * 1000).toISOString();
            this.messages.push({code: 'EXP_ERROR', message: `VC expired at ${exp}`, exp: payload.exp, now});
        }

        if (!payload.verifiableCredential) {
            this.messages.push({code: 'INVALID_VC', message: `no credentials found in presentation`, payload});
        }
        else {
            for (const vc of payload.verifiableCredential) {
                await this.parseCredentialToken(vc, payload.holder);
            }
        }
    }

    private async parseVCDMCredential(payload:any, holder?:string)
    {
        var ec:ExtractedCredential= {
            holder,
            issuer: payload?.iss,
            claims: payload.credentialSubject,
            metadata: {}
        };

        if (payload.credentialStatus) {
            if (Array.isArray(payload.credentialStatus)) {
                ec.metadata!.statusLists = payload.credentialStatus;
            }
            else {
                ec.metadata!.statusLists = [payload.credentialStatus];
            }
        }
        if (payload?.status && payload?.status?.status_list) {
            // if we have IETF Status Token lists, push it as a regular status list type
            if (!ec.metadata!.statusLists) {
                ec.metadata!.statusLists = [{type: 'status+jwt', ...payload?.status?.status_list}];
            }
            else {
                ec.metadata!.statusLists.push({type: 'status+jwt', ...payload?.status?.status_list});
            }
        }
        if (ec.metadata?.statusLists) {
            const msgs = await validateStatusLists(this.rp, ec);
            if (msgs.length) {
                this.messages = this.messages.concat(msgs);
            }
        }

        if (payload.evidence) {
            if (Array.isArray(payload.evidence)) {
                ec.metadata!.evidence = payload.evidence;
            }
            else {
                ec.metadata!.evidence = [payload.evidence];
            }
        }
        this.credentials.push(ec);
    }

    private async parseSDCredential(payload:any, token:string, holder?:string)
    {
        // TODO: Support SD-JWT
    }

    
}