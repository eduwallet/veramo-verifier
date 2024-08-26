import {resolve} from "path";

export function resolveConfPath(relativePath:string) {
    const path = process.env.CONF_PATH ? resolve(process.env.CONF_PATH) : resolve('../../conf');
    return `${path}/${relativePath}`;
}
