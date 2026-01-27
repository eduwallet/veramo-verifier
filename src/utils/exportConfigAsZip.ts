import archiver from 'archiver';
import { Response } from "express";

export interface ArchiveFile {
    path: string;
    name: string;
    content: string;
}

export async function exportConfigAsZip(res:Response, files:ArchiveFile[])
{
    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.pipe(res);

    files.forEach((file) => {
        archive.append(file.content, {name: (file.path ?? '' ) + '/' + file.name });
    });
     
    archive.finalize();
}
