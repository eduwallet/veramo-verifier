export interface StatusRequest {
    statusList: string;
    index: number;
}

interface CachedList {
    id: string;
    retrieved: Date;
    expires: Date;
}

interface CachedLists {
    [x:string]: CachedList;
}

export class StatusList
{
    private static cachedLists:CachedLists = {}

    private static statusListIsAvailable(statusList:string)
    {
        if (!StatusList.cachedLists[statusList]) {
            return false;
        }
        const now = new Date();
        if (StatusList.cachedLists[statusList].expires < now) {
            return false;
        }
        return true;
    }

    private static async retrieveList(statusList:string)
    {

    }

    private static async getStatusList(statusList:string)
    {
        if (!StatusList.statusListIsAvailable(statusList)) {
            await StatusList.retrieveList(statusList);
        }
    }

    public static async checkStatus(request:StatusRequest): Promise<boolean>
    {
        const list:CachedList = StatusList.getStatusList(request.statusList);
        
        return false;
    }
}
