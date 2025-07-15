import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { CoreAuthService } from "../auth.service";
import { Inject, UnauthorizedException } from "@nestjs/common";
import { AUTH_CONFIG_TOKEN, AuthModuleOptions } from "../interfaces/auth-module-options.interface";
import { Payload } from "../interfaces/payload-interface";
import { createJwtStrategyOptions } from "../utilities/jwt-strategies.helper";


export class AccessJwtStrategy extends PassportStrategy(Strategy, 'access-jwt') {
    constructor(private readonly authService: CoreAuthService<Payload>,
        @Inject(AUTH_CONFIG_TOKEN) private readonly authConfig: AuthModuleOptions
    ) {
        super(createJwtStrategyOptions('access-jwt', authConfig))
    }

    async validate(payload: Payload): Promise<Payload> {
        try {
            const user = await this.authService.findById(payload.sub);
            return user;
        } catch (error) {
            throw new UnauthorizedException('Unauthorized access');
        }

    }
}


export class RefreshJwtStrategy extends PassportStrategy(Strategy, 'refresh-jwt') {
    constructor(private readonly authService: CoreAuthService<Payload>,
        @Inject(AUTH_CONFIG_TOKEN) private readonly authConfig: AuthModuleOptions
    ) {
        super(createJwtStrategyOptions('refresh-jwt', authConfig))
    }

    async validate(payload: Payload): Promise<Payload> {
        try {
            const user = await this.authService.findById(payload.sub);
            return user;
        } catch (error) {
            throw new UnauthorizedException('Unauthorized access');
        }

    }
}