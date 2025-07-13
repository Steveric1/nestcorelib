# NestCoreLib

**NestCoreLib** is a plug-and-play utility library for NestJS applications that helps you rapidly scaffold and integrate essential backend features. It offers a complete solution for user management with JWT authentication, two-factor authentication (2FA), rate limiting, request caching, and secure WebSocket communication — all designed to be modular, secure, and production-ready.

---

## ✨ Features (more coming soon)

- ✅ **User Management with JWT Authentication**  
  Secure and scalable user authentication with customizable token expiration and refresh logic.

- 🔐 **Two-Factor Authentication (2FA)**  
  Time-based one-time password (TOTP) support with QR code generation for improved account security.

- 🚦 **Flexible Rate Limiting**  
  Apply global or route-specific throttling to prevent abuse and ensure API reliability.

- ⚡ **Request Caching**  
  Built-in support for Redis or in-memory caching to boost performance and reduce load.

- 🔌 **WebSocket Gateway Protection**  
  Authenticate WebSocket connections using JWT tokens for real-time, secure communication.

- ⚙️ **Modular Architecture**  
  Import only the features you need. Each module is fully decoupled and easily configurable.

- 🛡️ **Security & Extensibility First**  
  Designed with modern security practices and extensible APIs to adapt to real-world needs.
*

---

## 📦 Installation

Using **npm**:

```bash
npm install @nestcorelib/core-lib

Or using yarn:

yarn add install @nestcorelib/core-lib
```

## 🚀 Basic Usage
To get started, simply import the module you need into your AppModule or feature module.

```ts
import { AuthModule } from '@nestcorelib/core-lib';

@Module({
  imports: [
    AuthModule.register({
      jwtSecret: process.env.JWT_SECRET,
      expiresIn: '1h',
    }),
  ],
})
export class AppModule {}
```
### 🧩 User Management (Service Layer)

NestCoreLib provides a ready-to-use AuthService with full user management functionality out of the box. Simply extend it, and you’re good to go — no boilerplate required. You can also override or extend any method to add custom logic.

```ts
import { AuthService } from '@nestcorelib/core-lib';
import { Injectable } from '@nestjs/common';
import { User } from './entities/user.entities'; // Works with both Prisma and TypeORM models

@Injectable()
export class TestService extends AuthService<User, Dto> {}

```

### User Management (Controller Layer)

NestCoreLib also offers a prebuilt AuthController that exposes all necessary routes for user authentication and management. You can extend it directly to start using it immediately, and optionally override methods or decorators to apply custom DTOs, pipes, guards, etc.

```ts
import { User as userEntity } from './entities/user.entities';
import { AuthController } from '@nestcorelib/core-lib';

@Controller('test')
export class TestController extends AuthController {}
```

#### 💡 Notes

* Both AuthService and AuthController are fully typed and generic — giving you flexibility to integrate with your specific User entity and DTOs.
* Whether you're using Prisma or TypeORM, NestCoreLib supports both ORMs out of the box.