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
import { fromString } from "uint8arrays";
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { decodeSdJwt, getClaims } from '@sd-jwt/decode';
import { Verifier } from '@sd-jwt/types'
import { digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import { findKeyOfJwt } from 'utils/findKeyOfJwt';
import { VCDM2SD } from './validations/vcdmsd';
import { sdjwt } from './validations/sdjwt';
import { VCDM2 } from './validations/vcdm2';
import { VCDM1 } from './validations/vcdm1';
import { stringOrListAttribute } from '@utils/stringOrListAttribute';

export interface MetaData {
    [x:string]: any;
}

export interface ExtractedCredential {
    type?:string;
    credentialType?:string[];
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
                    await VCDM1(this);
                    break;
                case 'vc+jwt':
                    await VCDM2(this);
                    break;
                case 'vc+sd-jwt':
                    await VCDM2SD(this);
                    break;
                case 'dc+sd-jwt':
                    await sdjwt(this);
            }
        }
        catch (e:any) {
            console.error('Caught ' + e);
            this.messages.push({code: 'INVALID_PRESENTATION', message: this.credentialId + ': caught error validating ' + this.definition.format + ' response'});
        }
    }

    public async extractSDJwtCredential(jwt:JWT, token:string)
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
                case 'vct':
                    ec.credentialType = [verified.payload.vct];
                    break;
                default:
                    ec.claims[key] = verified.payload[key];
                    break;                
            }
        }

        this.credentials.push(ec);
        return ec;
    }

    public async extractVCDMCredentials(vp:any)
    {
        const vpType = stringOrListAttribute(vp, 'type');
        if (!vpType || !vpType.includes('VerifiablePresentation')) {
            this.messages.push({code: 'VC_ERROR', message: this.credentialId + `: presentation has incorrect type`});
            return;
        }
        if (!vp.verifiableCredential || !Array.isArray(vp.verifiableCredential) || vp.verifiableCredential.length == 0) {
            this.messages.push({code: 'VC_ERROR', message: this.credentialId + `: presentation has no embedded credentials`});
            return;
        }

        for (const cred of vp.verifiableCredential) {
            let credentialToken = cred; // this is the default VCDM 1.1 situation: assume it is a jwt_vc_json
            let format = 'jwt_vc_json';
            if (typeof(cred) == 'object') {
                const credType = stringOrListAttribute(cred, 'type');
                if (credType && credType.includes('EnvelopedVerifiableCredential') && cred.id && cred.id.length) {
                    // expect it to be data:<type>,<token>, so split on the comma once
                    const els = cred.id.split(',', 2);
                    if (els && els.length == 2) {
                        // in theory we could expect a application/vc+sd-jwt, but it was considered silly to send a
                        // SD-JWT using a VerifiablePresentation if you can also send it as KB-JWT. So DIIPv5 only
                        // actually uses application/vc+jwt (as it only supports VCDM 2.0)
                        if (els[0] == 'data:application/vc+jwt') {
                            credentialToken = els[1];
                            format = 'vc+jwt';
                        }
                        else if(els[0] == 'data:application/vc+sd-jwt') {
                            credentialToken = els[1];
                            format = 'vc+sd-jwt';
                        }
                        else {
                            this.messages.push({code: 'VC_ERROR', message: this.credentialId + ': embedded credential type not supported ' + els[0]});
                            credentialToken = null;
                        }
                    }
                }
                else {
                    this.messages.push({code: 'VC_ERROR', message: this.credentialId + ': embedded credential object not supported ' + JSON.stringify(cred)});
                    credentialToken = null;
                }
            }
            if (credentialToken) {
                await this.extractVCDMCredential(credentialToken, format, vp?.holder);
            }
        }
    }

    private contextIncludes(credential:any, ctx:string)
    {
        const ctxAttr = stringOrListAttribute(credential, '@context');
        if (!ctxAttr) {
            return false;
        }
        return ctxAttr.includes(ctx);
    }

    private async extractVCDMCredential(token:string, format:string, holder?:string)
    {
        let claims:any;
        const parts = token.split('~');
        const jwt = JWT.fromToken(parts[0]);
        if (format == 'vc+sd-jwt') {
            const decoded = await decodeSdJwt(token, digest);
            claims = await getClaims(decoded.jwt.payload, decoded.disclosures, digest) as any;
        }
        else {
            claims = jwt.payload;
        }

        const ec:ExtractedCredential= {
            type: this.definition.format,
            ...(holder && {holder}),
            issuer: claims.iss,
            claims: {},
            metadata: {}
        };

        // TODO: what do we really want to check here
        if (!claims.issuer) {
            this.messages.push({code: 'VC_ERROR', message: this.credentialId + `: credential is missing issuer information`});
            return;
        }

        if (typeof(claims.issuer) == 'string') {
            ec.issuer = claims.issuer;
        }
        else if(claims.issuer.id) {
            ec.issuer = claims.issuer.id;
        }
        let vc:any;

        switch (format) {
            case 'jwt_vc_json':
            {
                const credentialType1 = stringOrListAttribute(claims.vc, 'type');
                if (credentialType1) {
                    ec.credentialType = credentialType1;
                }
                if (claims.vc?.credentialSubject && this.contextIncludes(claims.vc, "https://www.w3.org/2018/credentials/v1")) {
                    this.messages.push({code: 'VCDM1.1', message: this.credentialId + `: credential is formatted according to VCDM1.1`});
                    claims = claims.vc;
                }
                else {
                    this.messages.push({code: 'VCDM1.1', message: this.credentialId + `: jwt_vc_json credential misses vc claim`});
                    return;
                }
                break;
            }
            case 'vc+jwt':
            case 'vc+sd-jwt':
            {
                const credentialType2 = stringOrListAttribute(claims, 'type');
                if (credentialType2) {
                    ec.credentialType = credentialType2;
                }

                if (claims.credentialSubject && this.contextIncludes(claims, "https://www.w3.org/ns/credentials/v2")) {
                    this.messages.push({code: 'VCDM2', message: this.credentialId + `: credential is formatted according to VCDM2`});
                }
                else {
                    this.messages.push({code: 'VCDM2', message: this.credentialId + `: vc+jwt credential misses credentialSubject claim`});
                    return;
                }
                break;
            }
            default:
                this.messages.push({code: 'VC_ERROR', message: this.credentialId + `: credential is missing claims`});
                return;
        }
        ec.claims = claims.credentialSubject;

        const statAttr = stringOrListAttribute(claims, 'credentialStatus');
        if (statAttr) {
            ec.metadata!.statusLists = statAttr;
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

        const evAttr = stringOrListAttribute(claims, 'evidence');
        if (evAttr) {
            ec.metadata!.evidence = evAttr;
        }

        const touAttr = stringOrListAttribute(claims, 'termsOfUse');
        if (touAttr) {
            ec.metadata!.termsOfUse = touAttr;
            
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
                debug("processing TA response content");
                hasError = await this.handleOIDFedIssuerPayload(jwt.payload, ec);
            }

            if (!hasError) {
                this.messages.push({code: 'OIDFED_OK', message: 'credential fed successfully resolved against the TA'});
            }
        }
        catch (e:any) {
            debug("Caught error while resolving trust chain for ", entity, url, e);
            this.messages.push({code: 'OIDFED_ERROR', message: 'credential fed claim cannot be resolved ' + entity});
        }
    }

    private async handleOIDFedIssuerPayload(payload:any, ec:ExtractedCredential)
    {
        let retval = false;

        // check that the key used to sign the credential is actually in the metadata vc_issuer list
        if (ec.issuer) {
            debug("resolving issuer of the credential", ec.issuer);
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
                    if (ec.type == 'dc+sd-jwt' && ec.credentialType?.includes(ccf.vct)) {
                        credIdFound = true;
                    }
                    else if (ec.type == 'vc+sd-jwt' || ec.type == 'jwt_vc_json' || ec.type == 'vc+jwt') {
                        const ctype = stringOrListAttribute(ccf.credential_definition, 'type');
                        const ectypes = ec.credentialType?.filter((i) => i != 'VerifiableCredential') || [];
                        const filteredTypes = ctype?.filter((i) => i != 'VerifiableCredential') || [];
                        // TODO: this limits our implementation to credentials with only 2 types: 'VerifiableCredential' and the specific type
                        if (ectypes.length && filteredTypes.length && ectypes[0] == filteredTypes[0]) {
                            credIdFound = true;
                        }
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