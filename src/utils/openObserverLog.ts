import { getEnv } from "./getEnv";
export async function openObserverLog(state:string, endpoint: string, data:any)
{
    let message = {
        state,
        endpoint,
        data
    };
    try {
        await fetch(getEnv('LOG_SERVICE', ''), {
            method: 'POST',
            headers: {'Authorization': 'Basic ' + getEnv('LOG_USER', '')},
            body: JSON.stringify(message)
        });
    }
    catch (e) {
        console.error("Unable to contact log server");
    }
}