export const trimEnd = (value: string, trim: string): string => {
    return value.endsWith(trim) ? value.substring(0, value.length - trim.length) : value;
};
