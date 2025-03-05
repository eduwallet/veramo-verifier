import { CryptoKey } from "./CryptoKey";
import { Ed25519 } from "./Ed25519";
import { X25519 } from "./X25519";
import { Secp256r1 } from './Secp256r1';
import { Secp256k1 } from './Secp256k1';

export const Factory = {
    createFromType: (keyType:string, privateKeyHex?:string):CryptoKey => {
        let key:CryptoKey;
        switch (keyType.toLocaleLowerCase()) {
            case 'ed25519':
                key = new Ed25519();
                break;
            case 'x25519':
                key = new X25519();
                break;
            case 'secp256r1':
                key = new Secp256r1();
                break;
            case 'secp256k1':
                key = new Secp256k1();
                break;
            default:
                throw new Error("key type " + keyType + " notsupported");
        }

        if (privateKeyHex) {
            key.initialisePrivateKey(privateKeyHex);
        }
        return key;
    },

    createFromDidKey(didKey:string) {
        let key:CryptoKey;

        if (didKey.startsWith('did:key:z6Mk')) {
            key = new Ed25519();
        }
        else if(didKey.startsWith('did:key:z6LS')) {
            key = new X25519();
        }
        else if(didKey.startsWith('did:key:zQ3s') || didKey.startsWith('did:key:z7r8')) {
            key = new Secp256k1();
        }
        else if(didKey.startsWith('did:key:zDn')) {
            key = new Secp256r1();
        }
        else {
            throw new Error("did key " + didKey.substring(0,8) + "... not supported.");
        }
        key.importFromDid(didKey);
        return key;
    }
}

