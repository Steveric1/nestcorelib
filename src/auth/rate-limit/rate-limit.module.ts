import { DynamicModule, Module } from "@nestjs/common";
import { RATE_LIMIT_OPTIONS, RateLimitOptions } from "./rate.limit.interface";
import { ThrottlerModule } from "@nestjs/throttler";
import { APP_GUARD } from '@nestjs/core';
import { RateLimitGuard } from "./rate.limit.guards";


@Module({})
export class RateLimitModule {
    static forRoot(options: RateLimitOptions): DynamicModule {
        const ttl = options.global.ttl || parseInt(process.env.RATE_LIMIT_TTL ?? '60', 10);
        const limit = options.global.limit || parseInt(process.env.RATELIMIT_LIMIT ?? '100', 10);

        const throttlerConfig: any = { ttl, limit }

        if (options.storage) {
            throttlerConfig.storage = options.storage;
        }

        if (options.isKeyGenerator) {
            throttlerConfig.keyGenerator = typeof options.keyGenerator === 'function' ? options.keyGenerator : ((req: any) => req.ip);
        }

        if (options.isMessage) {
            throttlerConfig.message = options.message || 'Too many requests, please try again later.';
            throttlerConfig.statusCode = options.statusCode || 429; // Default to 429 Too Many Requests
        }

        return {
            module: RateLimitModule,
            imports: [ThrottlerModule.forRoot(throttlerConfig)],
            providers: [
                {
                    provide: RATE_LIMIT_OPTIONS,
                    useValue: options,
                },
                RateLimitGuard,
                {
                    provide: APP_GUARD,
                    useClass: RateLimitGuard,
                },
            ],
            exports: [RATE_LIMIT_OPTIONS, ThrottlerModule, RateLimitGuard],
        }
    }
}