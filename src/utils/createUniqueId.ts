import { v4 } from 'uuid';

export function createUniqueId()
{
    const uuid = v4();
    return uuid.replace(/[\W_\s]+/g,"");
}