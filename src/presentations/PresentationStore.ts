import { loadJsonFiles } from "@utils/loadJsonFiles";
import { resolveConfPath } from "@utils/resolveConfPath";
import { PresentationDefinitionV2 } from '@sphereon/pex-models';

interface StoreType {
    [x:string]: PresentationDefinitionV2;
}

var _store:StoreType = {};

export function getPresentationStore() {
    return _store;
}

export function initialisePresentationStore() {
    const options = loadJsonFiles<PresentationDefinitionV2>({path: resolveConfPath('presentations')});
    for (const opt of options.asArray) {
        _store[opt.id] = opt;
    }   
}
