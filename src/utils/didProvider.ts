import {KeyDIDProvider} from "../packages/did-key-provider/key-did-provider";
import {WebDIDProvider} from "@veramo/did-provider-web";
import {JwkDIDProvider} from "../packages/did-jwk-provider/jwk-did-provider";

export function createDidProvider() {
    return {
        ['did:web']: new WebDIDProvider({
            defaultKms: 'local',
        }),
        ['did:jwk']: new JwkDIDProvider({
            defaultKms: 'local'
        }),
        ['did:key']: new KeyDIDProvider({
            defaultKms: 'local'
        })
    }
}
