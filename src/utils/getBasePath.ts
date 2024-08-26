import { trimBoth } from './trimBoth'
import { getBaseUrl } from './getBaseUrl'

export function getBasePath(url?: URL | string) {
    const basePath = new URL(getBaseUrl(url)).pathname
    if (basePath === '' || basePath === '/') {
      return ''
    }
    return `/${trimBoth(basePath, '/')}`
  }