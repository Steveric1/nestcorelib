// src/index.ts

// Modules
export { CoreAuthResourceModule } from './auth/auth.module';

// Services
export * from './auth/auth.service';

// Controller
export * from './auth/auth.controller';

// Interfaces
export * from './auth/interfaces/auth-module-options.interface';
export * from './auth/interfaces/user-repository.interface';
export * from './auth/interfaces/base-user.interface';

// Decorators
export * from './auth/decorator/current-user.decorator';

// Factories / Repositories
export * from './auth/repositories/auth-repo.factory';
export * from './auth/repositories/prisma-user.repository';
export * from './auth/repositories/typeorm-user.repository';

// Utilities
export * from './auth/utilities/jwt-strategies.helper';
export * from './auth/utilities/auth.resource.utility';
export * from './auth/utilities/verification.utilities';
export * from './auth/utilities/auth.jwt';

// Dto
export * from './auth/dto/login.dto';
export * from './auth/dto/register.dto';
export * from './auth/dto/update.dto';

// BaseUser
export * from './auth/interfaces/base-user.interface'

// Mailer
export * from './auth/mail/send.mail';

// Guards
export * from './auth/guards/jwt-auth.guards';

// JWT Strategies
export * from './auth/jwt-strategies/jwt.strategies';

