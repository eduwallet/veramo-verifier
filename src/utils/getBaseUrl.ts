import { trimEnd } from './trimEnd'

export function getBaseUrl(url?: URL | string | undefined) {
    let baseUrl = url
    if (!baseUrl) {
      const envUrl = process.env.BASEURL;
      if (envUrl && envUrl.length > 0) {
        baseUrl = new URL(envUrl)
      }
    }
    if (!baseUrl) {
      throw Error(`No base URL provided`)
    }
    return trimEnd(baseUrl.toString(), '/');
}