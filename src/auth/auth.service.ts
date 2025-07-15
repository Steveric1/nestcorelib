

// All what I will be building for basic authentication
/**
 * UserManagmentService: This Service will handle user management tasks such as creating,
 * updating, and deleting users. It will also handle user roles and permissions.
 *     Algorithm: CRUD operations for user management, role-based access control.
 *                User import the UserManagementService and it expect a UserRepository
 *               to interact with the database.
 * 
 *  usage: import { UserManagementService } from '@core-lib/auth/user-management.service';
 *  class AuthService {
 *    constructor(private readonly userManagementService: UserManagementService(UserEntity)) {}
 * }
 * 
 */

import { Inject, Injectable } from "@nestjs/common";
import { AUTH_REPO_TOKEN } from "./interfaces/auth-module-options.interface";
import { ResourceRepositoryInterface } from "./interfaces/user-repository.interface";
import { BaseUser } from "./interfaces/base-user.interface";



@Injectable()
export class CoreAuthService<TUser extends BaseUser, TCreateDto = Partial<BaseUser>> {
    constructor(@Inject(AUTH_REPO_TOKEN) private readonly authRepo: ResourceRepositoryInterface<TUser, TCreateDto>) {}

    async create(data: TCreateDto, role?: string): Promise<TUser> {
        return this.authRepo.create(data, role)
    }

    async findById(id: string | number): Promise<TUser> {
        return this.authRepo.findById(id);
    }

    async findAll(): Promise<TUser[]> {
        return this.authRepo.findAll();
    }

    async update(id: string | number, data: TCreateDto): Promise<TUser> {
        return this.authRepo.update(id, data);
    }

    async delete(id: string | number): Promise<{ message: string }> {
        return this.authRepo.delete(id);
    }

    async findByEmail(email: string): Promise<TUser> {
        return this.authRepo.findByEmail(email);
    }

    async findByUsername(username: string):Promise<TUser> {
        return this.authRepo.findByUsername(username);
    }

    async login(data: TCreateDto): Promise<any> {
        return this.authRepo.login(data);
    }

    async refreshToken(token: string) {
        return this.authRepo.refreshToken(token)
    }

    async resetPassword(token: string, newPassword: string): Promise<TUser> {
        return this.authRepo.resetPassword(token, newPassword);
    }

    async forgotPassword(email: string): Promise<void> {
        return this.authRepo.forgotPassword(email);
    }

    async forgotPasswordOtp(email: string): Promise<void> {
        return this.authRepo.forgotPasswordOtp(email);
    }

    async resetPasswordOtp(otp: string, email: string, newPassword: string): Promise<TUser> {
        return this.authRepo.resetPasswordOtp(otp, email, newPassword);
    }

    async verifyEmail(token: string): Promise<{ success: true, message: string }> {
        return this.authRepo.verifyEmail(token);
    }

    async verifyOtp(otp: string, email: string): Promise<{ success: true, message: string }> {
        return this.authRepo.verifyOtp(otp, email);
    }

    async resendOtp(email: string): Promise<{ success: true, message: string }> {
        return this.authRepo.resendOtp(email);
    }
}