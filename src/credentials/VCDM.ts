import { JWT } from "jwt/JWT";
import { Credential } from "./Credential";
import moment from 'moment';

export class VCDM extends Credential {
    private jwt:JWT|null = null;

    constructor(token:string)
    {
        super();
        this.parse(token);
    }

    public parse(token:string)
    {
        this.jwt = JWT.fromToken(token);

        if (this.jwt.payload.issuer) {
            if (typeof this.jwt.payload.issuer == 'string') {
                this.issuerKey = this.jwt.payload.issuer;
            }
            if (this.jwt.payload.issuer.id) {
                this.issuerKey = this.jwt.payload.issuer.id;
                this.issuerName = this.jwt.payload.issuer.name;
            }
        }

        // if we have a 'vc' subcredential, treat it as an old-skool credential
        if (this.jwt.payload.credentialSubject && !this.jwt.payload.vc) {
            this.format = 'vc+jwt';
            this.data = this.jwt.payload.credentialSubject;
            this.holder = this.jwt.payload.credentialSubject.id;

            this.statusLists = this.jwt.payload.credentialStatus ?? [];
            this.metadata.evidence = this.jwt.payload.evidence ?? null;
            this.metadata.issuedAt = this.jwt.payload.validFrom ? moment(this.jwt.payload.validFrom) : null;
            this.metadata.expires = this.jwt.payload.validUntil ? moment(this.jwt.payload.validUntil) : null;
        }
        else if(this.jwt.payload.vc && this.jwt.payload.vc.credentialSubject) {
            this.format = 'jwt_vc_json';
            this.data = this.jwt.payload.vc.credentialSubject;
            this.holder = this.jwt.payload.vc.credentialSubject.id;

            this.statusLists = this.jwt.payload.vc.credentialStatus ?? [];
            this.metadata.evidence = this.jwt.payload.vc.evidence ?? null;
            this.metadata.issuedAt = this.jwt.payload.vc.issuanceDate ? moment(this.jwt.payload.vc.issuanceDate) : null;
            this.metadata.expires = this.jwt.payload.vc.expirationDate ? moment(this.jwt.payload.vc.expirationDate) : null;
        }

        // statusList can be a single object, or a list of objects -> convert to array always
        if (!Array.isArray(this.statusLists)) {
            this.statusLists = [this.statusLists];
        }
        if (!this.holder && this.jwt.payload.sub) {
            this.holder = this.jwt.payload.sub;
        }
        if (!this.metadata.expires && this.jwt.payload.exp) {
            this.metadata.expires = moment(this.jwt.payload.exp);
        }
        if (!this.metadata.issuedAt && this.jwt.payload.iat) {
            this.metadata.issuedAt = moment(this.jwt.payload.iat);
        }
        if (!this.metadata.issuedAt && this.jwt.payload.nbf) {
            this.metadata.issuedAt = moment(this.jwt.payload.nbf);
        }
        this.payload = this.jwt.payload;
    }

    public async verify(): Promise<boolean>
    {
        const key = await this.jwt?.findKey();
        if (!key) {
            return false;
        }
        return this.jwt!.verify(key!);
    }
}