export const trimStart = (value: string, trim: string): string => {
    return value.startsWith(trim) ? value.substring(trim.length) : value;
};
  