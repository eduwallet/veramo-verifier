import {IDIDManagerCreateArgs, IIdentifier} from "@veramo/core";
import {generatePrivateKeyHex, TKeyType, toJwk} from "@sphereon/ssi-sdk-ext.key-utils";
import { loadJsonFiles } from './loadJsonFiles';
import { resolveConfPath } from './resolveConfPath';
import { agent } from '../agent';

export async function getIdentifier(did: string, alias?:string): Promise<IIdentifier | void> {
    var retval = await agent.didManagerGet({did}).catch(() => {});
    
    if (alias && !retval) {
        retval = await agent.didManagerGetByAlias({alias}).catch(() => {});
    }
    return retval;
}

interface IDIDOpts {
    did?: string
    didAlias?: string
    did_vm?: string
    createArgs?: IDIDManagerCreateArgs
    privateKeyHex?: string
}

interface IDIDResult extends IDIDOpts {
    identifier?: IIdentifier
}

export async function createDids(): Promise<IDIDResult[]> {
    const options = loadJsonFiles<IDIDOpts>({path: resolveConfPath('dids')});
    const result = options.asArray.map(async opts => {
        console.log(`DID config found for: ${opts.did}/${opts.didAlias}`)
        const did = opts.did || '';
        let identifier = (did || opts.didAlias) ? await getIdentifier(did, opts.didAlias) : undefined

        if (identifier) {
            console.log(`Identifier exists for DID ${did}/${opts.didAlias}`)
            console.log(`${JSON.stringify(identifier)}`)
            identifier.keys.map(key => console.log(`kid: ${key.kid}:\r\n ` + JSON.stringify(toJwk(key.publicKeyHex, key.type), null, 2)))
        } else {
            console.log(`No identifier for DID ${did}/${opts.didAlias} exists yet. Will create the DID...`)

            let args = opts.createArgs
            if (!args) {
                args = {options: {}}
            }

            // @ts-ignore
            const privateKeyHex = generatePrivateKeyHex((args.options?.type ?? args.options.keyType ?? "Secp256k1") as TKeyType)
            if (args.options && !('key' in args.options)) {
                // @ts-ignore
                args.options['key'] = {privateKeyHex}
                // @ts-ignore
            } else if (args.options && 'key' in args.options && args.options.key && typeof args.options?.key === 'object' && !('privateKeyHex' in args.options.key)) {
                // @ts-ignore
                args.options.key['privateKeyHex'] = privateKeyHex
            }

            identifier = await agent.didManagerCreate(args)
            identifier.keys.map(key => console.log(`kid: ${key.kid}:\r\n ` + JSON.stringify(toJwk(key.publicKeyHex, key.type), null, 2)))

            console.log(`Identifier created for DID ${did}`)
            console.log(`${JSON.stringify(identifier, null, 2)}`)
        }

        return {...opts, did, identifier} as IDIDResult
    });
    return Promise.all(result)
}
