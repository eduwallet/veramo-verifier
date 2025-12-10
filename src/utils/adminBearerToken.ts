export function adminBearerToken()
{
    return ('' + process.env.BEARER_TOKEN).trim();
}

export function hasAdminBearerToken()
{
    return process.env.BEARER_TOKEN && adminBearerToken().length > 0;
}