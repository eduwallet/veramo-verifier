import { getDbConnection } from '#root/database/index';
import { Verifier, Identifier, Presentation } from '#root/database/entities/index';
import { sendErrorResponse } from '#root/server/sendErrorResponse'
import { ArchiveFile, exportConfigAsZip } from '#root/utils/exportConfigAsZip';
import { Request, Response } from 'express'

export async function exportConfig(request: Request, response: Response) {
    try {
        response.set({
            'Content-Type': 'application/zip',
            'Content-Disposition': 'attachment; filename="configuration.zip"',
        });
        await exportConfigAsZip(response, await createFiles());
        return response;
    } 
    catch (e) {
        return sendErrorResponse(response, 500, {
                error: (e as Error).message,
            },
            e
        );
    }
}

async function createFiles()
{
    return [
        ...await addPresentations(),
        ...await addDids(),
        ...await addVerifiers()
    ];
}

async function addPresentations(): Promise<ArchiveFile[]>
{
    const dbConnection = getDbConnection();
    const repo = dbConnection.getRepository(Presentation);
    const objs =  await repo.createQueryBuilder('presentation').orderBy("presentation.name").getMany();
    const retval:ArchiveFile[] = [];
    for (const obj of objs) {
        retval.push({content: presentationToJson(obj), path: '/presentations', name: obj.shortname + '.json'});
    }
    return retval;
}
function presentationToJson(obj:Presentation):string
{
    return JSON.stringify({
        id: obj.shortname,
        name: obj.name,
        purpose: obj.purpose,
        ...(obj.input_descriptors && ({input_descriptors: JSON.parse(obj.input_descriptors)})),
        ...(obj.query && ({query: JSON.parse(obj.query)}))
    }, null, 4);
}
async function addDids(): Promise<ArchiveFile[]>
{
    const dbConnection = getDbConnection();
    const ids = dbConnection.getRepository(Identifier);
    const objs =  await ids.createQueryBuilder('identifier')
        .innerJoinAndSelect("identifier.keys", "key")
        .orderBy("identifier.did").getMany();
    const retval:ArchiveFile[] = [];
    for (const obj of objs) {
        retval.push({content: didToJson(obj), path: '/dids', name: (obj.alias ?? obj.did) + '.json'});
    }
    return retval;
}
function didToJson(obj:Identifier):string
{
    return JSON.stringify({
        did: obj.did,
        ...(obj.alias && {alias: obj.alias}),
        ...(obj.path && {path: obj.path}),
        ...(obj.services && {service: obj.services}),
        type: obj.keys[0].type,
        provider: obj.provider
    }, null, 4);
}
async function addVerifiers(): Promise<ArchiveFile[]>
{
    const dbConnection = getDbConnection();
    const repo = dbConnection.getRepository(Verifier);
    const objs =  await repo.createQueryBuilder('verifier').orderBy("verifier.name").getMany();
    const retval:ArchiveFile[] = [];
    for (const obj of objs) {
        retval.push({content: verifierToJson(obj), path: '/verifiers', name: obj.name + '.json'});
    }
    return retval;
}
function verifierToJson(obj:Verifier):string
{
    return JSON.stringify({
        name: obj.name,
        path: obj.path,
        ...(obj.admin_token && {adminToken: obj.admin_token}),
        did: obj.did,
        presentations: JSON.parse(obj.presentations ?? '[]'),
        ...(obj.metadata && {metadata: JSON.parse(obj.metadata)})
    }, null, 4);
}