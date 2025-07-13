import { JwtSignOptions } from "@nestjs/jwt"
import * as jwt from 'jsonwebtoken';
import { JwtPayload } from 'jsonwebtoken';
import { AuthModuleOptions } from "../interfaces/auth-module-options.interface";


export type ExtendedJwtSignOptions = JwtSignOptions & {
    secret?: string,
    privateKey?: string,
};

// This function returns the options for signing JWT access tokens based on the provided AuthModuleOptions.
// It includes the expiration time, issuer, audience, subject, and algorithm.
export function jwtSignOptions(options: AuthModuleOptions): ExtendedJwtSignOptions {
    const signOptions: ExtendedJwtSignOptions = {
        expiresIn: options.jwt?.expiresIn || '1h',
        ...(options.jwt?.issuer ? { issuer: options.jwt.issuer } : {}),
        ...(options.jwt?.audience ? { audience: options.jwt.audience } : {}),
        ...(options.jwt?.subject ? { subject: options.jwt.subject } : {}),
        ...(options.jwt?.algorithm ? { algorithm: options.jwt.algorithm } : {})
    }


    // Check if the algorithm is RS256 or ES256 and set the privateKey or publicKey accordingly
    if (options.jwt?.algorithm === 'RS256' || options.jwt?.algorithm === 'ES256') {
        signOptions.privateKey = options.jwt?.privateKey;
    } else {
        signOptions.secret = options.jwt?.secret;
    }

    return signOptions;
}


// This function returns the options for signing JWT refresh tokens based on the provided AuthModuleOptions.
// It includes the expiration time, issuer, audience, subject, and algorithm.
export function jwtRefreshSignOptions(options: AuthModuleOptions): ExtendedJwtSignOptions {
    const signOptions: ExtendedJwtSignOptions = {
        expiresIn: options.jwt?.refreshTokenExpiresIn || '7d',
        ...(options.jwt?.issuer ? { issuer: options.jwt.issuer } : {}),
        ...(options.jwt?.audience ? { audience: options.jwt.audience } : {}),
        ...(options.jwt?.subject ? { subject: options.jwt.subject } : {}),
        ...(options.jwt?.algorithm ? { algorithm: options.jwt.algorithm } : {})
    }

    // Check if the algorithm is RS256 or ES256 and set the privateKey or publicKey accordingly
    if (options.jwt?.algorithm === 'RS256' || options.jwt?.algorithm === 'ES256') {
        signOptions.privateKey = options.jwt?.refreshTokenPrivateKey || options.jwt?.privateKey;
    } else {
        signOptions.secret = options.jwt?.refreshTokenSecret || options.jwt?.secret;
    }

    return signOptions;
}


// Jwt verification options
// This function returns the options for verifying JWT tokens based on the provided AuthModuleOptions.
export function jwtVerifyOptions(options: AuthModuleOptions, tokenType: 'access' | 'refresh' = 'access'): 
{ secret?: string, publicKey?: string } {
    const baseOptions = {
        ...(options.jwt?.issuer ? { issuer: options.jwt.issuer } : {}),
        ...(options.jwt?.audience ? { audience: options.jwt.audience } : {}),
        ...(options.jwt?.subject ? { subject: options.jwt.subject } : {}),
        ...(options.jwt?.algorithm ? { algorithm: options.jwt.algorithm || 'HS256' } : {})
    }

    if (options.jwt?.algorithm === 'RS256' || options.jwt?.algorithm === 'ES256') {
        return {
            ...baseOptions,
            publicKey: tokenType === 'refresh' ? options.jwt?.refreshTokenPublicKey || options.jwt?.publicKey : options.jwt?.publicKey,
        };
    } else {
        return {
            ...baseOptions,
            secret: tokenType === 'refresh' ? options.jwt?.refreshTokenSecret || options.jwt?.secret : options.jwt?.secret,
        };
    }
}



// export function signWithDynamicKey(
//     payload: JwtPayload,
//     options: AuthModuleOptions,
//     isRefresh = false
// ): string {
//     const algorithm = options.jwt?.algorithm || 'HS256';
//     const expiresIn = isRefresh
//         ? options.jwt?.refreshTokenExpiresIn || '7d'
//         : options.jwt?.resetExpiresIn || '1h';

//     const signOptions: jwt.SignOptions = {
//         algorithm,
//         expiresIn,
//         issuer: options.jwt?.issuer,
//         audience: options.jwt?.audience,
//         subject: options.jwt?.subject,
//     };

//     const key =
//         ['RS256', 'ES256'].includes(algorithm)
//             ? isRefresh
//                 ? options.jwt?.refreshTokenPrivateKey || options.jwt?.privateKey
//                 : options.jwt?.privateKey
//             : isRefresh
//             ? options.jwt?.refreshTokenSecret || options.jwt?.secret
//             : options.jwt?.secret;

//     if (!key) {
//         throw new Error('Missing signing key (secret or privateKey)');
//     }

//     return jwt.sign(payload, key, signOptions);
// }

type TimeString = `${number}${'s' | 'm' | 'h' | 'd' | 'w' | 'y'}`

export function signWitDynamicKey(
    payload: JwtPayload,
    options: AuthModuleOptions
): string {
    const algorithm = options.jwt?.algorithm || 'HS256';
    const expiresIn = (options.jwt?.resetExpiresIn || '1h') as TimeString;

    const signOptions: jwt.SignOptions = {
        algorithm,
        expiresIn,
        ...(options.jwt?.issuer ? { issuer: options.jwt.issuer } : {}),
        ...(options.jwt?.audience ? { audience: options.jwt.audience } : {}),
        ...(options.jwt?.subject ? { subject: options.jwt.subject } : {}),
    };

    const key = ['RS256', 'ES256'].includes(algorithm)
        ? options.jwt?.privateKey
        : options.jwt?.secret;

    if (!key) {
        throw new Error('Missing signing key (secret or privateKey)');
    }

    const token = jwt.sign(payload, key, signOptions);
    return token;
}



export function verifyWithDynamicKey(
    token: string,
    options: AuthModuleOptions
): JwtPayload {
    const algorithm = options.jwt?.algorithm || 'HS256';

    const verifyOptions: jwt.VerifyOptions = {
        algorithms: [algorithm],
        ...(options.jwt?.issuer ? { issuer: options.jwt.issuer } : {}),
        ...(options.jwt?.audience ? { audience: options.jwt.audience } : {}),
    };

    const key =
        ['RS256', 'ES256'].includes(algorithm)
            ? options.jwt?.publicKey
            : options.jwt?.secret;

    if (!key) {
        throw new Error('Missing verification key (secret or publicKey)');
    }

    return jwt.verify(token, key, verifyOptions) as JwtPayload;
}
