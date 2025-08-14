// factories/auth-repo.factory.ts
import { DataSource } from "typeorm";
import { ResourceRepositoryInterface } from "../interfaces/user-repository.interface";
import { TypeOrmResourceRepository } from "./typeorm-user.repository";
import { PrismaResourceRepository } from "./prisma-user.repository";
import { AUTH_CONFIG_TOKEN, ENTITY_TOKEN, AuthModuleOptions, PRISMA_CLIENT_TOKEN } from "../interfaces/auth-module-options.interface";
import { JwtService } from "@nestjs/jwt";
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Mailer, MAILER } from "../interfaces/mail-sms.interface";
import type { Cache } from 'cache-manager';


export const TypeOrmRepoFactory = {
    provide: 'ResourceRepositoryInterface',
    useFactory: async (
        options: AuthModuleOptions,
        entity: any,
        dataSource: DataSource,
        jwtService: JwtService,
        mailer: Mailer,
        cache: Cache,
    ): Promise<ResourceRepositoryInterface> => {
        const model = dataSource.getRepository(entity);
        return new TypeOrmResourceRepository<any, any>(options, mailer, model, jwtService, cache);
    },
    inject: [AUTH_CONFIG_TOKEN, ENTITY_TOKEN, DataSource, JwtService, MAILER, CACHE_MANAGER],
};

export const PrismaRepoFactory = {
    provide: 'ResourceRepositoryInterface',
    useFactory: async (
        options: AuthModuleOptions,
        prisma: any,
        cache: Cache,
        jwtService: JwtService,
        mailer: Mailer
    ): Promise<ResourceRepositoryInterface> => {
        return new PrismaResourceRepository<any, any>(options, mailer, prisma, cache, jwtService);
    },
    inject: [AUTH_CONFIG_TOKEN, PRISMA_CLIENT_TOKEN, CACHE_MANAGER, JwtService, MAILER],
};
