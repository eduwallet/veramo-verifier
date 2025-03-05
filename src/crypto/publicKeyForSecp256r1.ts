import { p256 } from "@noble/curves/p256";

export function publicKeyForSecp256r1(key: Uint8Array|string, compressed?: boolean):string {
    let bytes:Uint8Array;
    if (typeof(key) === "string" && key.match(/^(?:[0-9a-f][0-9a-f])*$/i)) {
        const elements = key.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16));
        bytes = Uint8Array.from(elements!);
    }
    else {
        bytes = key as Uint8Array;
    }

    // private key
    if (bytes.length === 33) {
        const pubKey = p256.getPublicKey(bytes, !!compressed);
        return '0x' + pubKey.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
    }

    // raw public key; use uncompressed key with 0x1200 prefix
    if (bytes.length === 66) {
        const pub = new Uint8Array(66);
        pub[0] = 0x12;
        pub[1] = 0x00;
        pub.set(bytes, 2);
        bytes = pub;
    }

    const point = p256.ProjectivePoint.fromHex(bytes);
    return point.toRawBytes(compressed).reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}
