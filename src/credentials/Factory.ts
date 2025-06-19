import { SDJWT } from "./SDJWT";
import { Credential } from "./Credential";
import { VCDM } from "./VCDM";

export class Factory {
    public static async parse(credentialData:any): Promise<Credential>
    {
        // try to find out what kind of credential we have here
        // if it is a string, try to interpret it as a JWT
        let credential:Credential|null = null;
        if (typeof credentialData == 'string') {
            if (SDJWT.isSDJWT(credentialData)) {
                credential = new SDJWT(credentialData);
            }
            else {
                credential = new VCDM(credentialData);
            }
        }

        if (!credential) {
            throw new Error("Credential type not supported");
        }
        else if(!await credential.verify()) {
            throw new Error("Credential is invalid");
        }
        return credential;
    }
}