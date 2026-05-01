import { Factory } from "@muisit/cryptokey";
import { JWT } from "@muisit/simplejwt";
import { getDIDConfigurationStore } from "dids/Store";
import moment from "moment";
import { Verifier } from "verifier/Verifier";

export async function getOIDFedInfo(verifier:Verifier, date?:string) {
  const dids = getDIDConfigurationStore();
  const oidfedkey = await dids.get(process.env.OIDFED_KEY ?? 'oidfed');
  if (!oidfedkey) {
    throw new Error("Missing OIDFed key configuration");
  }

  const jwk = await Factory.toJWK(oidfedkey.key);
  const issuerJWK = await Factory.toJWK(verifier.key!);
  const metadata = verifier.getMetadata();
  const jwt = new JWT();
  jwt.header = {
    alg: oidfedkey.key.algorithms()[0],
    typ: 'entity-statement+jwt',
    kid: jwk.kid
  };

  jwt.payload = {
    "iss": process.env.BASEURL + '/' + verifier.name,
    "sub": process.env.BASEURL + '/' + verifier.name,
    "iat": moment(date).unix(),
    "exp": moment(date).unix() + 300,
    "metadata": {
      "federation_entity": {
        "display_name": verifier.name,
        "contacts": [process.env.OIDFED_ADMIN_CONTACT]
      },
      "openid_credential_verifier": {
        "credential_verifier": {
          "credential_verifier_metadata": metadata
        }
      },
      "vc_verifier": {
        "jwks": [issuerJWK]
      }
    },
    "jwks": { "keys": [jwk]},
    "authority_hints": [process.env.OIDFED_AUTH]
  };

  await jwt.sign(oidfedkey.key, oidfedkey.key.algorithms()[0]);
  return jwt.token;
}
