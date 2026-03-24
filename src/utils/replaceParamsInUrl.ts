export function replaceParamsInUrl(url:string, params:any) {
    for (const key of Object.keys(params)) {
        const val = params[key];
        const re = new RegExp(':' + key, "g");
        url = url.replace(re, val);
    }
    return url;
}
