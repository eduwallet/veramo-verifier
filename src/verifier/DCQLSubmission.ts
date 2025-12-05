import { Message } from 'types';
import moment from 'moment';
import { RP } from './RP';
import { Presentation, PresentationResult } from 'types/authresponse';
import { CredentialPresentation, PresentationDefinition } from 'presentations/PresentationStore';
import { JWT } from '@muisit/simplejwt';
import { validateStatusLists } from './validateStatusLists';

export interface MetaData {
    [x:string]: any;
}

export interface ExtractedCredential {
    issuer?:string|undefined;
    holder?: string;
    claims: MetaData;
    metadata?: MetaData;
}

export class DCQLSubmission
{
    public rp:RP;
    public credentialId:string;
    public definition:CredentialPresentation;
    public presentation:Presentation;
    public credentials:ExtractedCredential[];
    public messages:Message[];

    public constructor(rp:RP, definition:CredentialPresentation, presentation:Presentation)
    {
        this.rp = rp;
        this.credentialId = definition.id;
        this.presentation = presentation;
        this.credentials = [];
        this.definition = definition;
        this.messages = [];
    }

    public async validate()
    {
        try {
            switch (this.definition.format) {
                default:
                case 'jwt_vc_json':
                    await this.validateVCDM();
                    break;

            }
        }
        catch (e) {
            this.messages.push({code: 'INVALID_PRESENTATION', message: this.credentialId + ': caught error validating ' + this.definition.format + ' response'});
        }
    }

    private async validateVCDM()
    {
        var tokens = this.presentation as string[];
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
                    this.messages.push({code: 'VC_NBF_ERROR', message: this.credentialId + `: VC is not valid before ${nbf}`, nbf: jwt.payload.nbf, now});
                }
                if (jwt.payload?.iat && jwt.payload.iat > now) {
                    const iat = moment(jwt.payload.iat * 1000).toISOString();
                    this.messages.push({code: 'VC_IAT_ERROR', message: this.credentialId + `: VC is issued in the future at ${iat}`, iat: jwt.payload.iat, now});
                }
                if (jwt.payload?.exp && jwt.payload.exp <= now) {
                    const exp = moment(jwt.payload.exp * 1000).toISOString();
                    this.messages.push({code: 'VC_EXP_ERROR', message: this.credentialId + `: VC expired at ${exp}`, exp: jwt.payload.exp, now});
                }

                if (!jwt.payload?.vp) {
                    this.messages.push({code: 'VC_ERROR', message: this.credentialId + `: no presentation found`});
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
            await this.extractVCDMCredential(cred, jwt.payload?.holder);
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
        var ec:ExtractedCredential= {
            holder,
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
            await validateStatusLists(this.rp, ec);
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

        return ec;
    }
}