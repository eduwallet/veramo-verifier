import {config as dotenvConfig} from "dotenv-flow";
dotenvConfig()

export function getEnv(key:string, defaultValue:string) {
    return process.env[key] || defaultValue;
}