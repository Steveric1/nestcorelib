import { ThrottlerStorage } from "@nestjs/throttler";


export interface RateLimitRules {
    path: string;
    ttl: number;
    limit: number
}

export interface RateLimitOptions {
    global: { ttl: number; limit: number };
    rules?: RateLimitRules[];
    storage?: ThrottlerStorage;

    isKeyGenerator?: boolean;
    keyGenerator?: (req: any) => string;

    isMessage?: boolean;
    message?: string;

    statusCode?: number;
}

export const RATE_LIMIT_OPTIONS = 'RATE_LIMIT_OPTIONS';