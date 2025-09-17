import { Response } from "express"

export function sendErrorResponse(response: Response, statusCode: number, message: string | object, error?: any) {
    let msg = message
    if (!msg) {
        msg = 'Internal Server Error'
        statusCode = 500
    }

    if (statusCode >= 500) {
        console.error(error?.stack)
        console.error(Error().stack)
    }
    if (response.headersSent) {
        return response
    }
    response.statusCode = statusCode
    if (typeof msg === 'string' && !msg.startsWith('{')) {
        msg = { error: msg }
    }
    if (typeof msg === 'string' && msg.startsWith('{')) {
        response.header('Content-Type', 'application/json')
        return response.status(statusCode).end(msg)
    }
    return response.status(statusCode).json(msg)
}