import { Credential } from "./Credential";

export class SDJWT extends Credential
{
    constructor(token:string)
    {
        super();
        this.parse(token);
    }

    public parse(token:string)
    {
        this.format = 'dc+sd-jwt';
    }

    public static isSDJWT(token:string)
    {
        // ~ cannot be the first character in an SD JWT
        if (token.indexOf('~') > 0) {
            const elements = token.split('.');
            if (elements.length == 3) {
                const sds = elements[2].split('~');
                // in theory, we could have 0 disclosures, but the ~ must be there, so we at least have 2 sds elements
                if (sds.length > 1) {
                    return true;
                }
            }
        }
        return false;
    }

    public async verify(): Promise<boolean>
    {
        return true;
    }
}