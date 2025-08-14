import { ExecutionContext, HttpException, Inject, Injectable } from "@nestjs/common";
import { ThrottlerGuard, ThrottlerStorage } from "@nestjs/throttler";
import { RATE_LIMIT_OPTIONS, RateLimitOptions } from "./rate.limit.interface";
import { Reflector } from "@nestjs/core";

@Injectable()
export class RateLimitGuard extends ThrottlerGuard {
    constructor(
        @Inject(ThrottlerStorage) protected readonly storageService: ThrottlerStorage,
        @Inject(Reflector) protected readonly reflector: Reflector,
        @Inject(RATE_LIMIT_OPTIONS) private readonly myOptions: any,
    ) {
        super(
            {
                throttlers: [{
                    ttl: myOptions.global.ttl,
                    limit: myOptions.global.limit,
                }],
            },
            storageService,
            reflector
        );
    }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const path = request.route?.path || request.url;

        // Check for path-specific rules
        if (this.myOptions.rules) {
            const matchingRule = this.myOptions.rules.find(rule => 
                this.pathMatches(rule.path, path)
            );

            if (matchingRule) {
                // Temporarily override settings for this request
                const originalTtl = this.myOptions.global.ttl;
                const originalLimit = this.myOptions.global.limit;

                this.myOptions.global.ttl = matchingRule.ttl;
                this.myOptions.global.limit = matchingRule.limit;

                try {
                    return await super.canActivate(context);
                } finally {
                    // Restore original settings
                    this.myOptions.global.ttl = originalTtl;
                    this.myOptions.global.limit = originalLimit;
                }
            }
        }

        return await super.canActivate(context);
    }

    protected async getTracker(req: Record<string, any>): Promise<string> {
        if (this.myOptions?.isKeyGenerator && typeof this.myOptions?.keyGenerator === 'function') {
            return this.myOptions.keyGenerator(req);
        }
        return req.ip;
    }

    private pathMatches(rulePath: string, requestPath: string): boolean {
        // Simple path matching - adjust as needed
        return rulePath === requestPath;
    }
}