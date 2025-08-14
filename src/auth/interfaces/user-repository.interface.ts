

// User Repository interface 

import { BaseUser, } from "./base-user.interface";

export interface ResourceRepositoryInterface<TUser extends BaseUser = BaseUser, TCreateDto = Partial<BaseUser>> {
    create(data: TCreateDto, role?: string): Promise<TUser>;
    findById(id: string | number): Promise<TUser>;
    findAll(): Promise<TUser[]>;
    update(id: string | number, data: TCreateDto): Promise<TUser>;
    delete(id: string | number): Promise<{ message: string }>;
    findByEmail(email: string): Promise<TUser>;
    findByUsername(username: string): Promise<TUser>;
    login(Data: TCreateDto): Promise<any>;
    refreshToken(token: string): Promise<any>;
    resetPassword(email: string, newPassword: string): Promise<TUser>;
    forgotPassword(email: string): Promise<void>;
    resetPasswordOtp(otp: string, email: string, newPassword: string): Promise<TUser>;
    forgotPasswordOtp(email: string): Promise<void>;
    verifyEmail(token: string): Promise<{ success: true, message: string }>;
    verifyOtp(otp: string, email: string): Promise<{ success: true, message: string }>;
    resendOtp(email: string): Promise<{ success: true, message: string }>;
    verifyPhoneOtp(otp: string, phone: string): Promise<{ success: true, message: string }>;
    resendPhoneOtp(phone: string): Promise<{ success: true, message: string }>;
}