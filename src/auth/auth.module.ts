/* eslint-disable @typescript-eslint/require-await */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable prettier/prettier */
// modules/auth-resource.module.ts
import { DynamicModule, Provider } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import {
    AUTH_CONFIG_TOKEN,
    ENTITY_TOKEN,
    ROLE_ENTITY_TOKEN,
    ADMIN_ENTITY_TOKEN,
    AuthModuleOptions,
    AuthModuleAsyncOptions,
    PRISMA_CLIENT_TOKEN,
} from "./interfaces/auth-module-options.interface";
import { PrismaRepoFactory, TypeOrmRepoFactory } from "./repositories/auth-repo.factory";
import { JwtModule } from "@nestjs/jwt";
import { PassportModule } from "@nestjs/passport";
import { CoreAuthController } from "./auth.controller";
import { CoreAuthService } from "./auth.service";
import { AccessJwtStrategy, RefreshJwtStrategy } from "./jwt-strategies/jwt.strategies";
import { DefaultMailer } from "./mail-and-sms/send.mail";
import { MAILER, SMS_SENDER } from "./interfaces/mail-sms.interface";
import { CacheModule } from "@nestjs/cache-manager";
import { CorelibSmsSender } from "./mail-and-sms/send.sms";


export class CoreAuthResourceModule {
    static forRoot(options: AuthModuleOptions): DynamicModule {
        const providers: Provider[] = [
            { provide: AUTH_CONFIG_TOKEN, useValue: options },
            { provide: ENTITY_TOKEN, useValue: options.Entity },
            AccessJwtStrategy,
            RefreshJwtStrategy,
            CoreAuthService,
            { provide: MAILER, useClass: DefaultMailer},
            { provide: SMS_SENDER, useClass: CorelibSmsSender },
        ];

        const typeOrmEntities = options.orm === 'typeorm' ? [options.Entity] : [];

        // Add role entity
        if (options.roleEntity) {
            providers.push({ provide: ROLE_ENTITY_TOKEN, useValue: options.roleEntity });
            typeOrmEntities.push(options.roleEntity);
        }

        // Add admin entity
        if (options.adminEntity) {
            providers.push({ provide: ADMIN_ENTITY_TOKEN, useValue: options.adminEntity });
            typeOrmEntities.push(options.adminEntity);
        }

        // Conditionally register ORM-specific provider
        if (options.orm === 'prisma') {
            if (!options.PrismaClient) {
                throw new Error('PrismaClient must be provided when using Prisma ORM');
            }

            providers.push({ provide: PRISMA_CLIENT_TOKEN, useValue: options.PrismaClient });
            providers.push(PrismaRepoFactory);
        } else {
            providers.push(TypeOrmRepoFactory);
        }

        const CacheModuleOptions = options.cache?.provider === 'memory' ? CacheModule.register({ isGlobal: true }) :
            options.cache?.provider === 'redis' || options.cache?.provider === 'custom' ? 
            CacheModule.register({ isGlobal: true, ...options.cache?.config }) : CacheModule.register({ isGlobal: true });

        return {
            module: CoreAuthResourceModule,
            imports: [
                ...(options.orm === 'typeorm' ? [TypeOrmModule.forFeature(typeOrmEntities)] : []),
                JwtModule.register({
                    ...(options.jwt?.algorithm === 'RS256' || options.jwt?.algorithm === 'ES256' ?
                        {
                            privateKey: options.jwt?.privateKey,
                            publicKey: options.jwt?.publicKey
                        } : {
                            secret: options.jwt?.secret
                        }
                    ),
                    signOptions: {
                        expiresIn: options.jwt?.expiresIn || '1h',
                        ...(options.jwt?.issuer ? { issuer: options.jwt.issuer } : {}),
                        ...(options.jwt?.audience ? { audience: options.jwt.audience } : {}),
                        ...(options.jwt?.subject ? { subject: options.jwt.subject } : {}),
                        ...(options.jwt?.algorithm ? { algorithm: options.jwt.algorithm } : {})
                    }
                }),

                PassportModule.register({ defaultStrategy: 'access-jwt' }),
                // Register Cache based on what is provided in options
                CacheModuleOptions,
            ],
            providers,
            exports: [...providers, JwtModule, PassportModule, MAILER, CoreAuthService, CacheModuleOptions],
        };
    }

    static forRootAsync(options: AuthModuleAsyncOptions): DynamicModule {
        const asyncProvider = {
            provide: AUTH_CONFIG_TOKEN,
            useFactory: options.useFactory!,
            inject: options.inject || [],
        };


        const jwtModule = JwtModule.registerAsync({
            inject: [AUTH_CONFIG_TOKEN],
            useFactory: async (config: AuthModuleOptions) => ({
                 ...(config.jwt?.algorithm === 'RS256' || config.jwt?.algorithm === 'ES256' ?
                        {
                            privateKey: config.jwt?.privateKey,
                            publicKey: config.jwt?.publicKey
                        } : {
                            secret: config.jwt?.secret
                        }
                    ),
                signOptions: {
                    expiresIn: config.jwt?.expiresIn || '1h',
                    ...(config.jwt?.issuer ? { issuer: config.jwt.issuer } : {}),
                    ...(config.jwt?.audience ? { audience: config.jwt.audience } : {}),
                    ...(config.jwt?.subject ? { subject: config.jwt.subject } : {}),
                    ...(config.jwt?.algorithm ? { algorithm: config.jwt.algorithm } : {})
                }
            })
        })

        const cacheModule = CacheModule.registerAsync({
            inject: [AUTH_CONFIG_TOKEN],
            useFactory: async (config: AuthModuleOptions) => {
                if (config.cache?.provider === 'redis' || config.cache?.provider === 'custom') {
                    return { isGlobal: true, ...config.cache.config };
                }
                return { isGlobal: true }; // memory by default
            }
        });
        

        return {
            module: CoreAuthResourceModule,
            imports: [
                ...(options.imports || []),
                PassportModule.register({ defaultStrategy: 'access-jwt' }),
                cacheModule,
                jwtModule,

            ],
            providers: [
                asyncProvider,
                AccessJwtStrategy,
                RefreshJwtStrategy,
                CoreAuthService,
                { provide: MAILER, useClass: DefaultMailer},
                { provide: SMS_SENDER, useClass: CorelibSmsSender },
                ...(options.extraProviders || [])
            ],
            exports: [JwtModule, PassportModule, asyncProvider, MAILER, CoreAuthService, cacheModule],
        };
    }
}
