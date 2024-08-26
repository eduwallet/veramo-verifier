import { trimEnd } from "./trimEnd";
import { trimStart } from "./trimStart";

export const trimBoth = (value: string, trim: string): string => {
    return trimEnd(trimStart(value, trim), trim);
};
