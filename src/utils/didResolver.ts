import {Resolver} from "did-resolver";
import { getDidKeyResolver } from "./didKeyResolver";
import { getDidWebResolver } from "./didWebResolver";
import { getDidJwkResolver } from "./didJwkResolver";

export function createDidResolver() {
    return new Resolver({
        ...getDidJwkResolver(),
        ...getDidKeyResolver(),
        ...getDidWebResolver()
    })
}