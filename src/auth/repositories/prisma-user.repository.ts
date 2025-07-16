import { BadRequestException, ConflictException, Inject, NotFoundException, UnauthorizedException } from "@nestjs/common";
import { ResourceRepositoryInterface } from "../interfaces/user-repository.interface";
import { AUTH_CONFIG_TOKEN, PRISMA_CLIENT_TOKEN } from "../interfaces/auth-module-options.interface";
import * as bcrypt from 'bcrypt';
import { stripPassword } from "../utilities/auth.resource.utility";
import { BaseUser } from "../interfaces/base-user.interface";
import { JwtService } from "@nestjs/jwt";
import { jwtRefreshSignOptions, jwtSignOptions } from "../utilities/auth.jwt";
import { Mailer, MAILER } from "../interfaces/mail.interface"
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { verificationType } from "../utilities/verification.utilities";
import type { Cache } from 'cache-manager';




export class PrismaResourceRepository<TUser extends BaseUser, TCreateDto = Partial<BaseUser>> 
implements ResourceRepositoryInterface<TUser, TCreateDto> {
    constructor(
        @Inject(AUTH_CONFIG_TOKEN) private readonly options: any,
        @Inject(MAILER) private readonly mailer: Mailer,
        @Inject(PRISMA_CLIENT_TOKEN) private readonly prisma: any,
        @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
        private readonly jwtService: JwtService
    ) {}

    private get model() {
        const model = this.options.PrismaModelName || 'user';
        const availableModels = Object.keys(this.prisma);

        if (!this.prisma[model]) {
            console.error(`[core-lib] Model '${model}' not found in PrismaClient.`);
            console.log('[core-lib] Available Prisma models:', availableModels);
            throw new Error(`Model ${model} not found in PrismaClient`);
        }

        return this.prisma[model];
    }

    async create(data: TCreateDto, role?: string): Promise<TUser> {
        // get the role from the options
        const roleFromEntity = role || (data as any)?.role || this.options.defaultRole || 'user';

        // check if user exist 
        const itExist = await this.model.findUnique({
            where: { email: (data as any)?.email }
        })

        // If user exist throw an error
        if (itExist) {
            throw new ConflictException(`User with email ${(data as any)?.email} already exist`);
        }

        // Hash user password
        const hashPassword = await this.hashPassword((data as any)?.password);

        // Remove role from the data
        const { role: _, password, ...rest } = data as any;
        // Create new user
        const newUser = await this.model.create({
            data: {
                ...rest,
                password: hashPassword,
                role: roleFromEntity,
            }
        })

        // If email verification is enabled or OTP is enabled, send verification email or OTP
        if (this.options.enableEmailVerification === true) {
            const subject = this.options.emailVerification?.subject || 'Verification Email';

            if (!newUser.id || !newUser.email) {
                throw new NotFoundException(`User with email ${(data as any)?.email} does not have an email address`);
            }

            await verificationType.sendVerification(newUser, 
                { type: 'token', purpose: 'email-verification', via: 'email' }, 
                this.options, this.cacheManager, subject
            );
        } else if (this.options.enableOtp === true) {
            const subject = this.options.emailVerification?.subject || 'OTP Verification';;
            if (!newUser.id || !newUser.email) {
                throw new NotFoundException(`User with email ${(data as any)?.email} does not have an email address`);
            }
            await verificationType.sendVerification(newUser, 
                { type: 'otp', purpose: 'email-verification', via: 'email' }, 
                this.options, this.cacheManager, subject
            );
        }

        // remove the password from the created User
        const userWithoutPassword = stripPassword(newUser)
        return userWithoutPassword
    }

    async findAll(): Promise<TUser[]> {
        // remove password from each user
        const users = await this.model.findMany();

        const userWithoutPassword = users.map(user => {
            const { password, ...userWithoutPassword } = user;
            return userWithoutPassword;
        })

        return userWithoutPassword;
    }

    async findById(id: string ): Promise<TUser> {
        const user = await this.model.findUnique({ where: { id }});

        if (!user) {
            throw new NotFoundException(`User with id ${id} not found`);
        }

        // remove password from the user
        const userWithoutPassword = stripPassword(user);
        return userWithoutPassword;
    }

    async update(id: string, data: TCreateDto): Promise<TUser> {
        const user = await this.model.findUnique({ where: { id: String(id) }});

        if (!user) {
            throw new NotFoundException(`User with id ${id} not found`);
        }

        // Hash password if it exists in the data
        let updatedData = { ...(data as any) };
        if ((data as any)?.password) {
            updatedData.password = await this.hashPassword((data as any).password);
        }

        // Update user
        const udpateUser = await this.model.update({
            where: { id },
            data: updatedData,
        })

        // remove password from the updated user
        const userWithoutPassword = stripPassword(udpateUser);
        return userWithoutPassword;
    }

    async delete(id: string ): Promise<{ message: string }> {
        const model = this.options.PrismaModelName || 'user';
        const user = await this.prisma[model].findUnique({ where: { id: String(id) }});

        if (!user) {
            throw new NotFoundException(`User with id ${id} not found`);
        }

        // Delete user
        await this.prisma[model].delete({ where: { id }});
        return { message: "user with "+ id +" deleted successfully" }
    }

    async findByEmail(email: string): Promise<TUser> {
        const user = await this.model.findUnique({ where: { email }});

        if (!user) {
            throw new NotFoundException(`User with email ${email} not found`);
        }

        // remove password from the user
        const userWithoutPassword = stripPassword(user);
        return userWithoutPassword;
    }

    async findByUsername(username: string): Promise<TUser> {
        const user = await this.model.findUnique({ where: { username }});

        if (!user) {
            throw new NotFoundException(`User with username ${username} not found`);
        }

        // remove password from the user
        const userWithoutPassword = stripPassword(user)
        return userWithoutPassword;
    }

    async login(data: TCreateDto): Promise<any> {
        const user = await this.model.findUnique({
            where: { email: (data as any)?.email }
        })

        if (!user) {
            throw new UnauthorizedException(`Invalid email or password for user with email ${(data as any)?.email}`);
        }

        // check if user is verified and this check when consumer set verified in thier schema
        if (user?.verified === false) {
            throw new UnauthorizedException(`User with email ${(data as any)?.email} is not verified`);
        }

        // Verify password
        const isPasswordValid = await this.verifyHashPassword((data as any)?.password, user.password);
        if (!isPasswordValid) {
            throw new UnauthorizedException(`Invalid password for user with email ${(data as any)?.email}`)
        }

        // remove password
        const userWithoutPassword = stripPassword(user);

        // Generate token
        const tokens = this.generateToken(userWithoutPassword);
        return {
            user: userWithoutPassword,
            token: tokens
        }
    }

    async verifyEmail(token: string): Promise<{ success: true, message: string }> {
        try {
            if (!token) {
                throw new BadRequestException('Token is required for email verification');
            }
    
            // decode the token to get the user id
            const decoded = await verificationType.verify({
                type: 'token', value: token, purpose: 'email-verification'}, this.options
            )
            
            if (!decoded) {
                throw new BadRequestException('Invalid verification token');
            }
    
            // Find the user by id
            const user = await this.findById(decoded);
            if (!user) {
                throw new NotFoundException(`User with id ${decoded} not found`);
            }

            if (user.verified) {
                throw new ConflictException(`User with email ${user.email} is already verified`);
            }
    
            // update the user to set verified to true
            user.verified = true;
            await this.model.update({
                where: { id: user.id },
                data: { verified: true }
            });
            
            return {
                success: true,
                message: 'Email verified successfully'    
            };
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                throw new UnauthorizedException('Verification token has expired');
            } else if (error.name === 'JsonWebTokenError') {
                throw new UnauthorizedException('Invalid verification token');
            } else {
                throw new UnauthorizedException(`Token verification failed: ${error.message}`);
            }
        }
    }


    async verifyOtp(otp: string, email: string): Promise<{ success: true; message: string; }> {
        try {
            if (!otp || !email) {
                throw new BadRequestException('Email and OTP are required for verification');
            }
    
            const verificationEmail = await verificationType.verify({
                type: 'otp', value: otp, purpose: 'email-verification', email },
                this.options, this.cacheManager
            );
    
            
            const user = await this.model.findUnique({
                where: { email: verificationEmail }
            })
    
            if (!user) {
                throw new NotFoundException(`User with email ${verificationEmail} not found`);
            }

            // If user is already verified, throw an error
            if (user.verified) {
                throw new ConflictException(`User with email ${user.email} is already verified`);
            }

            // update the user to set verified to true
            user.verified = true;
            await this.model.update({
                where: { email: user.email },
                data: { verified: true }
            })
            return {
                success: true,
                message: 'Email verified successfully'
            };
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                throw new UnauthorizedException('OTP has expired');
            } else if (error.name === 'JsonWebTokenError') {
                throw new UnauthorizedException('Invalid OTP');
            } else {
                throw new UnauthorizedException(`OTP verification failed: ${error.message}`);
            }
        }
    }

    async resendOtp(email: string): Promise<{ success: true; message: string; }> {
        // find user by email
        const user = await this.findByEmail(email);

        if (!user) {
            throw new NotFoundException(`User with email ${email} not found`);
        }

        if (!user.id || !user.email) {
            throw new NotFoundException(`User with email ${email} does not have an email address`);
        }
        // send otp to user email
        const subject = this.options.emailVerification?.subject || 'OTP Verification';
        await verificationType.sendVerification(user, { type: 'otp', purpose: 'email-verification', via: 'email' },
            this.options, this.cacheManager, subject
        )

        return { success: true, message: `OTP sent to ${email}` };
    }
    
    async resetPassword(token: string, newPassword: string): Promise<TUser> {
        try {
            // decode the token to get the user id
            const decoded = await verificationType.verify({
                type: 'token', value: token, purpose: 'password-reset'}, this.options, this.cacheManager
            );

            // If the decoded token is not valid, it will throw an error
            if (!decoded) {
                throw new BadRequestException('Invalid reset token');
            }

            const user = await this.findById(decoded);
            
            // Check if the user exists
            if (!user) {
                throw new NotFoundException(`User with id ${decoded} not found`);
            }

            // Hash the new password
            const hashedPassword = await this.hashPassword(newPassword);

            // Update the user password
            const updatedUser = await this.model.update({
                where: { id: user.id },
                data: { password: hashedPassword }
            })

            // remove password from the updated user
            const userWithoutPassword = stripPassword(updatedUser);
            return userWithoutPassword;
        } catch (error) {
            console.error(error); // For debugging
            if (error.name === 'TokenExpiredError') {
                throw new UnauthorizedException('Reset token has expired')
            } else if (error.name === 'JsonWebTokenError') {
                throw new UnauthorizedException('Invalid reset token');
            } else {
                throw new UnauthorizedException(`Token verification failed`);
            }
        }
    }

    async refreshToken(token: string): Promise<any> {
        try {
            const decoded = this.jwtService.verify(token, jwtRefreshSignOptions(this.options));
            const user = await this.findById(decoded.sub);

            if (!user) {
                throw new NotFoundException(`User with id ${decoded.sub} not found`);
            }

            // Generate new tokens
            const newToken = this.generateToken(user);
            return { newToken }
        } catch (error) {
            throw new UnauthorizedException(`Invalid refresh token: ${error.message}`);
        }
    }

    async forgotPassword(email: string) {
        // find user by email
        const user = await this.findByEmail(email);
        console.log(user.email)
    
        if (!user) {
            throw new NotFoundException(`User with email ${email} not found`);
        }

        const subject = this.options.emailVerification?.subject || 'Password Reset Request';
    
        if (!user.id || !user.email) {
            throw new NotFoundException(`User with email ${email} does not have an email address`);
        }

        await verificationType.sendVerification({ id: user.id, email: user.email }, {type: 'token', purpose: 'password-reset', via: 'email'},
            this.options, this.cacheManager, subject
        )
    }

    async forgotPasswordOtp(email: string) {
        // find user by email
        const user = await this.findByEmail(email);

        if (!user) {
            throw new NotFoundException(`User with email ${email} not found`);
        }

        const subject = this.options.emailVerification?.subject || 'OTP for Password Reset';
        await verificationType.sendVerification(user,
            { type: 'otp', purpose: 'password-reset', via: 'email' },
            this.options, this.cacheManager, subject)
        
    }

    async resetPasswordOtp(otp: string, email: string, newPassword: string): Promise<TUser> {
        try {
            if (!otp || !email) {
                throw new BadRequestException('Email and OTP are required for password reset');
            }

            // verify the OTP
            const verificationEmail = await verificationType.verify({
                type: 'otp', value: otp, purpose: 'password-reset', email
                }, this.options, this.cacheManager);
            
            // find user by email
            const user = await this.model.findUnique({
              where: { email: verificationEmail }
            });

            if (!user) {
               throw new NotFoundException(`User with email ${verificationEmail} not found`);
            }

            // Hash the new password
            const hashedPassword = await this.hashPassword(newPassword);
            // Update the user password
            const updatedUser = await this.model.update({
                where: { email: user.email },
                data: { password: hashedPassword }
            });

            // remove password from the updated user
            const userWithoutPassword = stripPassword(updatedUser);
            return userWithoutPassword;
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                throw new UnauthorizedException('OTP has expired');
            } else if (error.name === 'JsonWebTokenError') {
                throw new UnauthorizedException('Invalid OTP');
            } else {
                throw new UnauthorizedException(`OTP verification failed: ${error.message}`);
            }
        }
    }

    private generateToken(user: BaseUser) {
        return {
            accessToken: this.generateAccessToken(user),
            refreshToken: this.generateRefreshToken(user)
        }
    }

    private generateAccessToken(user: BaseUser): string {
        const payload = {
            email: user.email,
            sub: user.id,
            role: user.role,
        }

        return this.jwtService.sign(payload, jwtSignOptions(this.options));
    }

    private generateRefreshToken(user: BaseUser): string {
        const payload = {
            email: user.email,
            sub: user.id,
            role: user.role,
        }

        return this.jwtService.sign(payload, jwtRefreshSignOptions(this.options));
    }

    private async hashPassword(password: string): Promise<string> {
        return bcrypt.hash(password, 10);
    }
    
    private async verifyHashPassword(plainPassword: string, hashPasword: string): Promise<boolean> {
        return await bcrypt.compare(plainPassword, hashPasword);
    }

};