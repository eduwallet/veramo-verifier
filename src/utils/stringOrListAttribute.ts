export function stringOrListAttribute(obj:any, field:string) : string[] | null
{
    if (obj[field]) {
        if (Array.isArray(obj[field])) {
            return obj[field] as string[];
        }
        else {
            return [obj[field]];
        }
    }
    return null;
}