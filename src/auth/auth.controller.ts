import { Body, Delete, Get, Injectable, Param, Post, Put, Query, UseGuards } from "@nestjs/common";
import { CoreAuthService } from "./auth.service";
import { BaseUser } from "./interfaces/base-user.interface";
import { AccessGuard } from "./guards/jwt-auth.guards";
import { CurrentUser } from "./decorator/current-user.decorator";


@Injectable()
export class CoreAuthController<TUser extends BaseUser, TCreateDto=Partial<BaseUser>> {
    constructor(private readonly authService: CoreAuthService<TUser, TCreateDto>) {}

    @Post('register')
    async register(@Body() data: TCreateDto): Promise<TUser> {
        return await this.authService.create(data)
    }

    @Post('login')
    async login(@Body() data: TCreateDto) {
        return await this.authService.login(data)
    }

    @Get('users')
    async getAll(): Promise<TUser[]> {
        return await this.authService.findAll();
    }

    @Get('user/:id')
    async getById(@Param('id') id: string | number): Promise<TUser> {
        return await this.authService.findById(id)
    }

    @Get('refresh-token')
    async refreshToken(@Body() token: string) {
        return this.authService.refreshToken(token)
    }

    @Get('verify-email')
    async verifyEmail(@Query('token') token: string): Promise<{ success: true, message: string }> {
        return await this.authService.verifyEmail(token);
    }

    @Post('verify-otp')
    async verifyOtp(@Body() data: { otp: string, email: string }): Promise<{ success: true, message: string }> {
        const { otp, email } = data;
        return await this.authService.verifyOtp(otp, email);
    }

    @Post('resend-otp')
    async resendOtp(@Body() data: { email: string }): Promise<{ success: true, message: string }> {
        const { email } = data;
        return await this.authService.resendOtp(email);
    }

    @Post('forgot-password')
    async forgotPassword(@Body() data: { email: string }): Promise<void> {
        const { email } = data;
        return await this.authService.forgotPassword(email);
    }

    @Post('reset-password')
    async resetPassword(@Body() data: { token: string, newPassword: string }): Promise<TUser> {
        const { token, newPassword } = data;
        return await this.authService.resetPassword(token, newPassword);
    }

    @Post('forgot-password-otp')
    async forgotPasswordOtp(@Body() data: { email: string }): Promise<void> {
        const { email } = data;
        return await this.authService.forgotPasswordOtp(email);
    }

    @Post('reset-password-otp')
    async resetPasswordOtp(@Body() data: { otp: string, email: string, newPassword: string }): Promise<TUser> {
        const { otp, email, newPassword } = data;
        return await this.authService.resetPasswordOtp(otp, email, newPassword);
    }

    @UseGuards(AccessGuard)
    @Get('profile')
    async getProfile(@CurrentUser() user: TUser): Promise<TUser> {
        // Assuming the user is already populated by the AccessGuard
        return user;
    }

    @Put('user/:id')
    async update(@Param('id') id: string | number, @Body() data: TCreateDto): Promise<TUser> {
        return await this.authService.update(id, data)
    }

    @Delete('user/:id')
    async delete(@Param('id') id: string | number) {
        return await this.authService.delete(id)
    }
}