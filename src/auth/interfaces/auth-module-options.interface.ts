import { PrismaClient } from "@prisma/client";
import { BaseUser } from "./base-user.interface";


export interface AuthModuleOptions {
    orm?: 'typeorm' | 'prisma';
    Entity?: any; //For TypeORM Users: class
    PrismaModelName?: keyof PrismaClient; //For Prisma Users: string
    PrismaClient?: any;
    defaultRole?: string;
    allowedRoles?: string[];
    roleEntity?: any;
    adminEntity?: any;
    cache?: {
        provider: 'memory' | 'redis' | 'custom';
        config?: {
            ttl: number;
            store?: any;
            host?: string;
            port?: number;
            password?: string;
        }
    }
    jwt?: {
        secret: string;
        expiresIn?: string;
        resetExpiresIn?: string;
        refreshTokenSecret?: string;
        refreshTokenExpiresIn?: string;
        issuer?: string;
        audience?: string;
        subject?: string;
        algorithm?: 'HS256' | 'RS256' | 'ES256';
        privateKey?: string; // For RS256 or ES256
        publicKey?: string; // For RS256 or ES256
        refreshTokenPrivateKey?: string;
        refreshTokenPublicKey?: string;
    };
    externalAuthProviders?: {
        google2FAKey?: string;
        [key: string]: any;
    };
    mailer?: {
        host?: string;
        port?: number;
        user?: string;
        pass?: string;
        from?: string;
    };
    emailVerification?: {
        subject?: string;
        htmlBuilder?: (token: string, user?: BaseUser) => string;
    };
    smsVerification?: {
        provider: 'twilio' | 'vonage' | 'custom';
        apiKey?: string;
        apiSecret?: string;
        from?: string;
        message?: (otp: string) => string; // Function to format the message
        senderId?: string;
        customSender?: (to: string, message: string) => Promise<void>;
    }
    enable2FA?: boolean;
    enableOtp?: boolean;
    enableSms?: boolean;

    enableEmailVerification?: boolean;
    rateLimiting?: boolean;
    lockoutOnFailedAttempts?: boolean;
    multiTenant?: boolean;
}


export interface AuthModuleAsyncOptions {
    useFactory?: (...args: any[]) => Promise<AuthModuleOptions> | AuthModuleOptions;
    inject?: any[];
    imports?: any[];
    useClass?: new (...args: any[]) => AuthModuleOptions;
    useExisting?: new (...args: any[]) => AuthModuleOptions;
    extraProviders?: any[];
    isGlobal?: boolean;
}

export const AUTH_CONFIG_TOKEN = 'AUTH_CONFIG_TOKEN';
export const ENTITY_TOKEN = 'ENTITY_TOKEN';
export const ROLE_ENTITY_TOKEN = 'ROLE_ENTITY';
export const ADMIN_ENTITY_TOKEN = 'ADMIN_ENTITY';
export const AUTH_REPO_TOKEN = 'ResourceRepositoryInterface';
export const PRISMA_CLIENT_TOKEN = 'PRISMA_CLIENT';