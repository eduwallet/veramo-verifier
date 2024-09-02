import {resolve} from "path";
import { getEnv } from "./getEnv";

export function resolveConfPath(relativePath:string) {
    const path = resolve(getEnv('CONF_PATH', './conf'));
    return `${path}/${relativePath}`;
}
