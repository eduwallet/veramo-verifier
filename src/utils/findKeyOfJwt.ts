import { JWT } from "@muisit/simplejwt";
import { Factory, CryptoKey } from "@muisit/cryptokey";

export async function findKeyOfJwt(jwt:JWT): Promise<CryptoKey | null>
{
    // this should return the key
    let ckey: CryptoKey | null = await jwt.findKey();
    if (ckey) {
        return ckey;
    }

    // if this fails for some reason, do the same thing here again

    // if there is a kid in the header, see if it can be resolved
    if (jwt.header?.kid) {
      const kid = jwt.header.kid.split("#")[0].trim("=");
      try {
        ckey = await Factory.resolve(kid);
      }
      catch (e) {
        // pass
      }
    }

    // keys can be defined as a JWK entry
    if (!ckey && jwt.header?.jwk) {
      ckey = await Factory.createFromJWK(jwt.header.jwk);
    }

    // the iss claim in the header can be a resolvable did
    if (!ckey && jwt.header?.iss) {
      try {
        ckey = await Factory.resolve(jwt.header.iss);
      }
      catch (e) {
        // pass
      }
    }

    // the iss claim may reside in the payload
    if (!ckey && jwt.payload?.iss) {
      try {
        ckey = await Factory.resolve(jwt.payload.iss);
      }
      catch (e) {
        // pass
      }
    }
    return ckey;
  }
