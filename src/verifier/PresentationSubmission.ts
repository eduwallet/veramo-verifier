import { PEX } from '@sphereon/pex';
import { IPresentation, JWTVerified, PresentationSubmission as PEXPresentationSubmission, PresentationDefinitionV2, verifyJWT } from 'externals';
import { resolver } from 'agent';
import { JWTPayload } from '@sphereon/did-auth-siop';
import { Message } from 'types';
import moment from 'moment';

// https://identity.foundation/presentation-exchange/spec/v2.0.0/
// Implementation of presentation exchange validation

interface ClaimList {
    [x:string]:string|number;
}

// https://w3c.github.io/vc-bitstring-status-list/#examples
export interface StatusList {
    id: string;
    type: string;
    statusPurpose: string;
    statusListIndex: string
    statusListCredential: string;
}

export interface ExtractedCredential {
    issuerKey: string;
    issuer?:string|undefined;
    holder: string;
    payload?: JWTPayload;
    claims: ClaimList;
    statusLists?: StatusList[];
}

export class PresentationSubmission
{
    public presentation:IPresentation;
    public submission:PEXPresentationSubmission;
    public definition:PresentationDefinitionV2;
    public pex:PEX;
    public credentials:ExtractedCredential[];
    public aud:string;

    public constructor(presentation:IPresentation, definition:PresentationDefinitionV2, submission: PEXPresentationSubmission, did:string)
    {
        this.presentation = presentation;
        this.submission = submission;
        this.definition = definition as PresentationDefinitionV2;
        this.pex = new PEX();
        this.credentials = [];
        this.aud = did;
    }

    public async verify():Promise<Message[]>
    {
        var retval:Message[] = [];
        // extract the credentials from the presentation. 
        for (const jwt of this.presentation.verifiableCredential!) {
            try {
                const decoded = await verifyJWT(
                    jwt as string,
                    {
                        resolver: resolver,
                        policies: { nbf: false, iat: false, exp: false, aud: false} // these cause exceptions before decoding
                    });
                if (!decoded.verified) {
                    retval.push({code: 'INVALID_VC', message: 'Could not verify VerifiableCredential in presentation', decoded});
                }
                else {
                    const now:number = Math.floor(Date.now() / 1000);

                    if (decoded.payload.nbf && decoded.payload.nbf > now) {
                        const nbf = moment(decoded.payload.nbf * 1000).toISOString();
                        retval.push({code: 'VC_NBF_ERROR', message: `VC is not valid before ${nbf}`, nbf: decoded.payload.nbf, now});
                    }
                    if (decoded.payload.iat && decoded.payload.iat > now) {
                        const iat = moment(decoded.payload.iat * 1000).toISOString();
                        retval.push({code: 'VC_IAT_ERROR', message: `VC is issued in the future at ${iat}`, iat: decoded.payload.iat, now});
                    }
                    if (decoded.payload.exp && decoded.payload.exp <= now) {
                        const exp = moment(decoded.payload.exp * 1000).toISOString();
                        retval.push({code: 'VC_EXP_ERROR', message: `VC expired at ${exp}`, exp: decoded.payload.exp, now});
                    }

                    if (decoded.payload.aud && decoded.payload.aud != this.aud) {
                        retval.push({code: 'VC_AUD_ERROR', message: `VC required a different audience`, aud: decoded.payload.aud, did: this.aud});
                    }

                    const ec:ExtractedCredential = this.extractVCJsonCredential(decoded);
                    this.credentials.push(ec);
                }
            }
            catch (e) {
                retval.push({code: 'INVALID_VC', message: 'Error while verifying VerifiableCredential'});
            }
        }

        try {
            const { value, warnings, errors } = this.pex.evaluatePresentation(this.definition, this.presentation, { presentationSubmission: this.submission });
            if(errors && errors.length > 0) {
                retval.push({code: 'INVALID_PRESENTATION', message: 'Error while verifying VerifiablePresentation', value, warnings, errors});
            }
        }
        catch (e) {
            retval.push({code: 'INVALID_PRESENTATION', message: 'Error while verifying VerifiablePresentation', error: e});
        }

        // It seems the whole implementation of presentationSubmission does not work (or at least the mutual interpretation does not match)
        // When requesting $.credentialSubject.given_name, the return path is '$', with a path_nested $.vp.verifiableCredential[0]
        // These paths both seem to point to the whole credential and not to the specific claim inside the credential.
        // As long as the whole process does not support requesting more than 1 credential (DIIP restriction), it does not really matter
        // of course: we always get the whole credential and the back-end can try and find out what to do with it.

        return retval;
    }

    private extractVCJsonCredential(jwt:JWTVerified):ExtractedCredential
    {
        var ec:ExtractedCredential= {
            issuerKey: jwt.issuer,
            holder: jwt.payload.sub!,
            issuer: jwt.payload.issuer.id ? jwt.payload.issuer.id : jwt.payload.issuer,
            payload: jwt.payload,
            claims: {}
        };

        if (jwt.payload.credentialSubject) {
            ec.claims = jwt.payload.credentialSubject;
        }

        if (jwt.payload.credentialStatus) {
            if (Array.isArray(jwt.payload.credentialStatus)) {
                ec.statusLists = jwt.payload.credentialStatus;
            }
            else {
                ec.statusLists = [jwt.payload.credentialStatus];
            }
        }

        return ec;
    }
}