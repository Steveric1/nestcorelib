import { ExtractJwt } from "passport-jwt";
import { AuthModuleOptions } from "../interfaces/auth-module-options.interface";


export function createJwtStrategyOptions(mode: 'access-jwt' | 'refresh-jwt', authConfig: AuthModuleOptions) {
    const algorithms = authConfig.jwt?.algorithm || 'HS256';
    const isAccess = mode === 'access-jwt';

    const secretOrKey = algorithms === 'HS256'
    ? (isAccess
        ? authConfig.jwt?.secret :
        authConfig.jwt?.refreshTokenSecret || authConfig.jwt?.secret)
    : (isAccess
        ? authConfig.jwt?.publicKey :
        authConfig.jwt?.refreshTokenPublicKey || authConfig.jwt?.publicKey
    );

    if (!secretOrKey) {
        throw new Error(`[${mode.toUpperCase()} JWT] Missing secret or key for JWT strategy`);
    }

    const options: any = {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        ignoreExpiration: false,
        secretOrKey,
        algorithms: [algorithms]
    };

    if (authConfig.jwt?.issuer) options.issuer = authConfig.jwt?.issuer;
    if (authConfig.jwt?.audience) options.audience = authConfig.jwt?.audience;

    return options
}