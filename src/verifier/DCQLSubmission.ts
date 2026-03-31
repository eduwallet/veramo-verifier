import Debug from 'debug';
const debug = Debug("verifier:dcqlsubmission");

import { DCQL, Message } from 'types';
import moment from 'moment';
import { RP } from './RP';
import { Presentation } from 'types/authresponse';
import { CredentialPresentation } from 'presentations/PresentationStore';
import { JWT } from '@muisit/simplejwt';
import { Factory } from '@muisit/cryptokey';
import { validateStatusLists } from './validateStatusLists';
import { fromString, toString } from "uint8arrays";
import { sha256 } from '@noble/hashes/sha2'
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { Verifier } from '@sd-jwt/types'
import { digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import { findKeyOfJwt } from 'utils/findKeyOfJwt';

export interface MetaData {
    [x:string]: any;
}

export interface ExtractedCredential {
    type?:string;
    id?:string;
    issuer?:string|undefined;
    holder?: string;
    claims: MetaData;
    metadata?: MetaData;
    name?: string;
}

export class DCQLSubmission
{
    public rp:RP;
    public query:DCQL;
    public credentialId:string;
    public definition:CredentialPresentation;
    public presentation:Presentation;
    public credentials:ExtractedCredential[];
    public messages:Message[];

    public constructor(rp:RP, query:DCQL, definition:CredentialPresentation, presentation:Presentation)
    {
        this.rp = rp;
        this.query = query;
        this.credentialId = definition.id;
        this.presentation = presentation;
        this.credentials = [];
        this.definition = definition;
        this.messages = [];
    }

    public async validate()
    {
        try {
            debug("presentation is ", this.presentation);
            debug("definitions is ", this.definition);
            switch (this.definition.format) {
                default:
                case 'jwt_vc_json':
                    await this.validateVCDM();
                    break;
                case 'dc+sd-jwt':
                    await this.validateSDJwt();
            }
        }
        catch {
            this.messages.push({code: 'INVALID_PRESENTATION', message: this.credentialId + ': caught error validating ' + this.definition.format + ' response'});
        }
    }

    private async validateSDJwt()
    {
        let tokens = this.presentation as string[];
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#appendix-B.3.6
        // presentationresult should be an array of string tokens
        if (!Array.isArray(tokens)) {
            this.messages.push({code: 'INVALID_PRESENTATION', message: this.credentialId + ': dc+sd-jwt expects array of JWT tokens'});
            tokens = [tokens];
        }

        // tokens is a list of SD-JWT with KB jwts
        for (const token of tokens) {
            if (typeof token !== 'string') {
                this.messages.push({code: 'INVALID_PRESENTATION', message: this.credentialId + ': dc+sd-jwt expects string SD-JWT tokens'});
            }
            else {
                await this.extractSDJwt(token);
            }
        }
    }

    private async extractSDJwt(token:string)
    {
        // extract the final JWT from the SD-JWT
        const parts = token.split('~');
        // the first part is the SD-JWT, the last part can be a KB-JWT
        let sdjwt;
        try {
            sdjwt = JWT.fromToken(parts[0]);
        }
        catch {
            this.messages.push({code: 'INVALID_JWT', message: this.credentialId + ': cannot decode SD-JWT'});
            return;
        }

        // if the last entry of the split is empty, it means there is no KB-JWT
        if (parts[parts.length - 1].length == 0) {
            this.messages.push({code: 'MISSING_KB', message: this.credentialId + ': dc+sd-jwt token does not have a key-binding JWT attached'});
        }
        else {
            await this.validateKBJwt(parts[parts.length - 1], sdjwt, token);
        }

        // validate the SD-JWT
        // the sdjwt.findKey() implementation is the same as in this class, but it resolved to null for some reason...
        const key = await findKeyOfJwt(sdjwt);
        if (!key) {
            this.messages.push({code: 'INVALID_SDJWT', message: this.credentialId + ': could not determine signing key of SD-JWT'});
        }
        else {
            const validatedJwt = await sdjwt.verify(key);
            if (!validatedJwt) {
                this.messages.push({code: 'INVALID_SDJWT', message: this.credentialId + ': could not verify signature of SD-JWT'});
            }
        }

        const now:number = Math.floor(Date.now() / 1000);

        if (sdjwt.payload?.nbf && sdjwt.payload.nbf > now) {
            const nbf = moment(sdjwt.payload.nbf * 1000).toISOString();
            this.messages.push({code: 'NBF_ERROR', message: this.credentialId + `: VC is not valid before ${nbf}`, nbf: sdjwt.payload.nbf, now});
        }
        if (sdjwt.payload?.iat && sdjwt.payload.iat > now) {
            const iat = moment(sdjwt.payload.iat * 1000).toISOString();
            this.messages.push({code: 'IAT_ERROR', message: this.credentialId + `: VC is issued in the future at ${iat}`, iat: sdjwt.payload.iat, now});
        }
        if (sdjwt.payload?.exp && sdjwt.payload.exp <= now) {
            const exp = moment(sdjwt.payload.exp * 1000).toISOString();
            this.messages.push({code: 'EXP_ERROR', message: this.credentialId + `: VC expired at ${exp}`, exp: sdjwt.payload.exp, now});
        }

        // then extract all hashes and provide them as attributes/claims
        await this.extractSDJwtCredential(sdjwt, token);       
    }

    private async extractSDJwtCredential(jwt:JWT, token:string)
    {
        const ec:ExtractedCredential= {
            type: this.definition.format,
            issuer: jwt.payload?.iss,
            claims: {},
            metadata: {}
        };

        // provide the cnf key as holder key
        if (jwt.payload?.cnf?.kid) {
            ec.holder = jwt.payload.cnf.kid;
        }
        else if(jwt.payload?.cnf?.jwk) {
            ec.holder = jwt.payload.cnf.jwk;
        }
        else if(jwt.payload?.cnf.x5c) {
            ec.holder = jwt.payload.cnf.x5c;
        }

        const ckey = await findKeyOfJwt(jwt);
        const verifier: Verifier = async (data: string, signature:string): Promise<boolean> => {
            return await ckey!.verify(ckey!.algorithms()[0], fromString(signature, 'base64url'), fromString(data, 'utf-8'))
        }
        const sdjwt = new SDJwtVcInstance({
            verifier,
            hasher: digest,
            hashAlg: 'sha-256',
            saltGenerator: generateSalt,
        });
        const verified = await sdjwt.verify(token, {}); // do not pass any required claims, just take whatever is there

        for (const key of Object.keys(verified.payload)) {
            // leave out some metadata claims
            switch (key) {
                case 'iss': // encoded in ec.issuer
                case 'cnf': // already encoded in holder
                case '_sd': // SD-JWT artifacts
                case '_sd_alg':
                case '_sd_hash':
                    break;
                case 'status':
                    if (verified.payload.status?.status_list) {
                        ec.metadata!.statusLists = [{type:'status+jwt', ...verified.payload.status.status_list}];
                        const msgs = await validateStatusLists(this.rp, ec);
                        if (msgs && msgs.length) {
                            this.messages = this.messages.concat(msgs);
                        }            
                    }
                    else {
                        this.messages.push({code:'NO_STATUS_LIST', message:'sd-jwt does not implement a correct status list'});
                    }
                    break;
                case 'fed':
                    if (typeof(verified.payload.fed) !== 'string') {
                        this.messages.push({code:'OIDFED_ERROR', message:'sd-jwt contains an invalid fed: claim'});
                    }
                    else {
                        await this.handleOIDFed(verified.payload.fed as string, ec);
                    }
                    break;
                case 'iat':
                    ec.metadata!.issuedAt = moment(verified.payload.iat! * 1000).toISOString();
                    break;
                case 'nbf':
                    ec.metadata!.notBefore = moment(verified.payload.nbf! * 1000).toISOString();
                    break;
                case 'exp':
                    ec.metadata!.expires = moment(verified.payload.exp! * 1000).toISOString();
                    break;
                default:
                    ec.claims[key] = verified.payload[key];
                    break;                
            }
        }

        this.credentials.push(ec);
        return ec;
    }

    private async validateKBJwt(token:string, sdjwt:JWT, hashableValue:string)
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
            this.messages.push({code: 'INVALID_JWT', message: this.credentialId + ': KB is not a valid JWT'}); 
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
                    this.messages.push({code: 'INVALID_SDJWT', message: this.credentialId + ': unsupported holder key type in SD-JWT'});
                }
            }
            catch {
                this.messages.push({code: 'INVALID_SDJWT', message: this.credentialId + ': holder key cannot be resolved'});
            }

            if (!holder) {
                this.messages.push({code: 'INVALID_SDJWT', message: this.credentialId + ': cannot determine holder key for SD-JWT to check KB signature'});
            }
            else {
                const isValidSignature = await jwt.verify(holder);
                if (!isValidSignature) {
                    this.messages.push({code: 'JWT_UNVERIFIED', message: this.credentialId + ': could not validate signature of KB with holder key'});
                }
                else {
                    this.messages.push({code: 'JWT_VERIFIED', message: this.credentialId + ': key binding was succesfully verified'});
                }
            }
        }

        if (!jwt.header?.typ || jwt.header.typ != 'kb+jwt') {
            this.messages.push({code: 'INVALID_KB', message: this.credentialId + ': invalid typ header'});
        }
        const now:number = Math.floor(Date.now() / 1000);
        if (jwt.payload?.nbf && jwt.payload.nbf > now) {
            const nbf = moment(jwt.payload.nbf * 1000).toISOString();
            this.messages.push({code: 'NBF_ERROR', message: this.credentialId + `: VC is not valid before ${nbf}`, nbf: jwt.payload.nbf, now});
        }
        if (jwt.payload?.iat && jwt.payload.iat > now) {
            const iat = moment(jwt.payload.iat * 1000).toISOString();
            this.messages.push({code: 'IAT_ERROR', message: this.credentialId + `: VC is issued in the future at ${iat}`, iat: jwt.payload.iat, now});
        }
        if (jwt.payload?.exp && jwt.payload.exp <= now) {
            const exp = moment(jwt.payload.exp * 1000).toISOString();
            this.messages.push({code: 'EXP_ERROR', message: this.credentialId + `: VC expired at ${exp}`, exp: jwt.payload.exp, now});
        }
        // check that nonce and aud are correct
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0-28.html#appendix-B.3.6
        if (!jwt.payload?.aud || (jwt.payload.aud != this.rp.verifier.clientId() && jwt.payload.aud != 'decentralized_identifier:' + this.rp.verifier.clientId())) {
            this.messages.push({code: 'INVALID_KB', message: this.credentialId + ': aud claim does not match client id of verifier'});
        }
        if (!jwt.payload?.nonce || jwt.payload.nonce != this.rp.session.data.nonce) {
            this.messages.push({code: 'INVALID_KB', message: this.credentialId + ': nonce claim does not match session nonce'});
        }

        const parts = hashableValue.split('~').slice(0, -1).join('~') + '~';
        const hashValue = toString(sha256(parts), 'base64url')
        if (!jwt.payload?.sd_hash) {
            this.messages.push({code: 'INVALID_KB', message: this.credentialId + ': missing hash over credential'});
        }
        else if (jwt.payload?.sd_hash != hashValue) {
            this.messages.push({code: 'INVALID_KB', message: this.credentialId + ': hash over credential does not match credential'});
        }
    }

    private async validateVCDM()
    {
        let tokens = this.presentation as string[];
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#appendix-B.1.3.1.5
        // presentationresult should be an array of string tokens
        if (!Array.isArray(tokens)) {
            this.messages.push({code: 'INVALID_PRESENTATION', message: this.credentialId + ': jwt_vc_json expects array of JWT tokens'});
            tokens = [tokens];
        }

        for (const token of tokens) {
            if (typeof token !== 'string') {
                this.messages.push({code: 'INVALID_PRESENTATION', message: this.credentialId + ': jwt_vc_json expects string JWT tokens'});
            }
            else {
                const jwt = JWT.fromToken(token);

                if (!jwt.payload?.aud || jwt.payload.aud != this.rp.verifier.clientId()) {
                    this.messages.push({code: 'INVALID_PRESENTATION', message: this.credentialId + ': aud claim does not match client id of verifier'});
                }
                if (!jwt.payload?.nonce || jwt.payload.nonce != this.rp.session.data.nonce) {
                    this.messages.push({code: 'INVALID_PRESENTATION', message: this.credentialId + ': nonce claim does not match session nonce'});
                }

                const now:number = Math.floor(Date.now() / 1000);

                if (jwt.payload?.nbf && jwt.payload.nbf > now) {
                    const nbf = moment(jwt.payload.nbf * 1000).toISOString();
                    this.messages.push({code: 'NBF_ERROR', message: this.credentialId + `: VC is not valid before ${nbf}`, nbf: jwt.payload.nbf, now});
                }
                if (jwt.payload?.iat && jwt.payload.iat > now) {
                    const iat = moment(jwt.payload.iat * 1000).toISOString();
                    this.messages.push({code: 'IAT_ERROR', message: this.credentialId + `: VC is issued in the future at ${iat}`, iat: jwt.payload.iat, now});
                }
                if (jwt.payload?.exp && jwt.payload.exp <= now) {
                    const exp = moment(jwt.payload.exp * 1000).toISOString();
                    this.messages.push({code: 'EXP_ERROR', message: this.credentialId + `: VC expired at ${exp}`, exp: jwt.payload.exp, now});
                }

                if (!jwt.payload?.vp) {
                    this.messages.push({code: 'INVALID_PRESENTATION', message: this.credentialId + `: no presentation found`});
                }
                else {
                    await this.extractVCDMCredentials(jwt);
                }
            }
        }
    }

    private async extractVCDMCredentials(jwt:JWT)
    {
        // TODO: make a difference between VCDM 1.1 and VCDM 2 presentations
        const vp = jwt.payload!.vp!;
        if (!vp.type || !Array.isArray(vp.type) || !vp.type.includes('VerifiablePresentation')) {
            this.messages.push({code: 'VC_ERROR', message: this.credentialId + `: presentation has incorrect type`});
            return;
        }
        if (!vp.verifiableCredential || !Array.isArray(vp.verifiableCredential) || vp.verifiableCredential.length == 0) {
            this.messages.push({code: 'VC_ERROR', message: this.credentialId + `: presentation has no embedded credentials`});
            return;
        }

        for (const cred of vp.verifiableCredential) {
            await this.extractVCDMCredential(cred, vp?.holder);
        }
    }

    private contextIncludes(credential:any, ctx:string)
    {
        if (!credential || !credential['@context'] || !Array.isArray(credential['@context'])) {
            return false;
        }
        return credential['@context'].includes(ctx);
    }

    private async extractVCDMCredential(token:string, holder?:string)
    {
        const jwt = JWT.fromToken(token);
        const ec:ExtractedCredential= {
            type: this.definition.format,
            ...(holder && {holder}),
            issuer: jwt.payload?.iss,
            claims: {},
            metadata: {}
        };

        // TODO: what do we really want to check here
        if (!jwt.payload?.issuer) {
            this.messages.push({code: 'VC_ERROR', message: this.credentialId + `: credential is missing issuer information`});
            return;
        }

        ec.issuer = jwt.payload!.issuer;
        let vc:any;

        if (jwt.payload?.vc?.credentialSubject && this.contextIncludes(jwt.payload?.vc, "https://www.w3.org/2018/credentials/v1")) {
            this.messages.push({code: 'VCDM1.1', message: this.credentialId + `: credential is formatted according to VCDM1.1`});
            vc = jwt.payload.vc;
        }
        else if (jwt.payload?.credentialSubject && this.contextIncludes(jwt.payload, "https://www.w3.org/ns/credentials/v2")) {
            this.messages.push({code: 'VCDM2.0', message: this.credentialId + `: credential is formatted according to VCDM2.0`});
            vc = jwt.payload;
        }
        else {
            this.messages.push({code: 'VC_ERROR', message: this.credentialId + `: credential is missing claims`});
            return;
        }
        ec.claims = vc.credentialSubject;

        if (vc.credentialStatus) {
            if (Array.isArray(vc.credentialStatus)) {
                ec.metadata!.statusLists = vc.credentialStatus;
            }
            else {
                ec.metadata!.statusLists = [vc.credentialStatus];
            }
            const msgs = await validateStatusLists(this.rp, ec);
            if (msgs && msgs.length) {
                this.messages = this.messages.concat(msgs);
            }
        }
        if (jwt.payload?.status && jwt.payload?.status?.status_list) {
            // if we have IETF Status Token lists, push it as a regular status list type
            if (!ec.metadata!.statusLists) {
                ec.metadata!.statusLists = [{type: 'status+jwt', ...jwt.payload?.status?.status_list}];
            }
            else {
                ec.metadata!.statusLists.push({type: 'status+jwt', ...jwt.payload?.status?.status_list});
            }
        }
        if (vc.evidence) {
            if (Array.isArray(vc.evidence)) {
                ec.metadata!.evidence = vc.evidence;
            }
            else {
                ec.metadata!.evidence = [vc.evidence];
            }
        }
        if (vc.termsOfUse) {
            if (Array.isArray(vc.termsOfUse)) {
                ec.metadata!.termsOfUse = vc.termsOfUse;
            }
            else {
                ec.metadata!.termsOfUse = [vc.termsOfUse];
            }
            for (const tou of ec.metadata!.termsOfUse) {
                if (tou.type == 'OpenIDFederation' && tou.policyId) {
                    await this.handleOIDFed(tou.policyId, ec);
                }
            }
        }

        this.credentials.push(ec);
        return ec;
    }

    private async handleOIDFed(entity:string, ec:ExtractedCredential)
    {
        const url = process.env.OIDFED_TA + '/resolve?sub=' + entity;
        try {
            const result = await fetch(url).then((r) => r.text());
            debug("oidfed resolution result is ", result);

            let jwt:JWT;
            try {
                jwt = JWT.fromToken(result);
            }
            catch (e) {
                debug("Caught error decoding TA response", e);
                this.messages.push({code: 'OIDFED_ERROR', message: 'credential fed claim cannot be resolved due to TA error ' + entity});
                return;
            }
            debug("result JWT is ", jwt);
            let hasError = false;

            const now:number = Math.floor(Date.now() / 1000);
            if (jwt.header?.typ != 'resolve-response+jwt') {
                this.messages.push({code: 'OIDFED_ERROR', message: this.credentialId + `: TA response has incorrect type`, type: jwt.header?.typ});
                hasError = true;
            }
            if (jwt.payload!.sub != entity) {
                this.messages.push({code: 'OIDFED_ERROR', message: this.credentialId + `: TA response has incorrect sub`, sub: jwt.payload?.sub, entity});
                hasError = true;
            }

            if (jwt.payload?.nbf && jwt.payload.nbf > now) {
                const nbf = moment(jwt.payload.nbf * 1000).toISOString();
                this.messages.push({code: 'OIDFED_ERROR', message: this.credentialId + `: TA response is not valid before ${nbf}`, nbf: jwt.payload.nbf, now});
                hasError = true;
            }
            if (jwt.payload?.iat && jwt.payload.iat > now) {
                const iat = moment(jwt.payload.iat * 1000).toISOString();
                this.messages.push({code: 'OIDFED_ERROR', message: this.credentialId + `: TA response is issued in the future at ${iat}`, iat: jwt.payload.iat, now});
                hasError = true;
            }
            if (jwt.payload?.exp && jwt.payload.exp <= now) {
                const exp = moment(jwt.payload.exp * 1000).toISOString();
                this.messages.push({code: 'OIDFED_ERROR', message: this.credentialId + `: TA response expired at ${exp}`, exp: jwt.payload.exp, now});
                hasError = true;
            }
            if (!jwt.payload?.iss || jwt.payload?.iss !== process.env.OIDFED_TA) {
                const ta = jwt.payload?.iss;
                this.messages.push({code: 'OIDFED_ERROR', message: this.credentialId + `: TA response is not issued by the trust anchor ${ta}`, ta: jwt.payload?.iss});
                hasError = true;
            }

            if (!hasError) {
                hasError = await this.handleOIDFedIssuerPayload(jwt.payload, ec);
            }

            if (!hasError) {
                this.messages.push({code: 'OIDFED_OK', message: 'credential fed successfully resolved against the TA'});
            }
        }
        catch (e) {
            debug("Caught error while resolving trust chain for ", entity, url);
            this.messages.push({code: 'OIDFED_ERROR', message: 'credential fed claim cannot be resolved ' + entity});
        }
    }

    private async handleOIDFedIssuerPayload(payload:any, ec:ExtractedCredential)
    {
        let retval = false;

        // check that the key used to sign the credential is actually in the metadata vc_issuer list
        if (ec.issuer) {
            const skey = await Factory.resolve(ec.issuer!);
            if (!skey) {
                this.messages.push({code: 'OIDFED_ERROR', message: `could not resolve credential signing key, failed to match OIDFed metadata`});
                retval = true;
            }
            else {
                if (!payload.metadata?.vc_issuer?.jwks) {
                    this.messages.push({code: 'OIDFED_ERROR', message: `TA metadata does not contain issuer signing keys`});
                    retval = true;
                }
                else {
                    let keyMatched = false;
                    for(const jwkspec of payload.metadata!.vc_issuer!.jwks) {
                        if (jwkspec.kid === ec.issuer) {
                            keyMatched = true;
                            break;
                        }
                        else {
                            const tkey = await Factory.createFromJWK(jwkspec);
                            if (tkey && skey.keyType === tkey.keyType && skey.exportPrivateKey() === tkey.exportPrivateKey() ) {
                                keyMatched = true;
                                break;
                            }
                        }
                    }

                    if (!keyMatched) {
                        this.messages.push({code: 'OIDFED_ERROR', message: `Issuer signing key not found in TA metadata`});
                        retval = true;
                    }
                }
            }
        }
        else {
            this.messages.push({code: 'OIDFED_ERROR', message: `trust chain issuer could not be matched with credential signing key due to absent issuer statement`});
            retval = true;
        }

        // check if the credential is present in the TA metadata credential list
        if (payload.metadata?.openid_credential_issuer?.credential_configurations_supported) {
            const ccs = payload.metadata?.openid_credential_issuer?.credential_configurations_supported;
            let credIdFound = false;
            for (const credid of Object.keys(ccs ?? {})) {
                const ccf = ccs[credid];

                if (ccf.format == ec.type) {
                    if (ec.type == 'dc+sd-jwt' && ccf.vct == ec.claims.vct) {
                        credIdFound = true;
                    }
                }
            }

            if (!credIdFound) {
                this.messages.push({code: 'OIDFED_ERROR', message: `trust chain issuer does not support this credential`});
                retval = true;
            }
        }
        else {
            this.messages.push({code: 'OIDFED_ERROR', message: `trust chain issuer does not support this credential`});
            retval = true;
        }

        return retval;
    }
}