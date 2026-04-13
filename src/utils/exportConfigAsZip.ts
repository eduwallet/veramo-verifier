import ZipArchive from 'archiver-node/zip';
import { Response } from "express";

export interface ArchiveFile {
    path: string;
    name: string;
    content: string;
}

export async function exportConfigAsZip(res:Response, files:ArchiveFile[])
{
    const archive = new ZipArchive({ zlib: { level: 9 } });

    files.forEach((file) => {
        archive.add(file.content, (file.path ?? '' ) + '/' + file.name);
    });
     
    const archiveDataStream = archive.write()
    archiveDataStream.pipe(res);
}
