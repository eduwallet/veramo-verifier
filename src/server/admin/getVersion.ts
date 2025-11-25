import { getBuildInfo } from '#root/utils/getBuildInfo';
import { Request, Response } from 'express'

export async function getVersion(request: Request, response: Response) {
    try {
        return response.json(getBuildInfo());
    } 
    catch (e) {
        response.header('Content-Type', 'application/json')
        return response.status(500).json({"error": JSON.stringify(e)});
    }
}
