import { Repository } from "typeorm";
import { ResourceRepositoryInterface } from "../interfaces/user-repository.interface";
import { BadRequestException, ConflictException, Inject, NotFoundException, UnauthorizedException } from "@nestjs/common";
import * as bcrypt from 'bcrypt'
import { AUTH_CONFIG_TOKEN, AuthModuleOptions } from "../interfaces/auth-module-options.interface";
import { stripPassword } from "../utilities/auth.resource.utility";
import { BaseUser } from "../interfaces/base-user.interface";
import { JwtService } from "@nestjs/jwt";
import { jwtRefreshSignOptions, jwtSignOptions, jwtVerifyOptions } from "../utilities/auth.jwt";
import { Mailer, MAILER } from "../interfaces/mail-sms.interface";
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { verificationType } from "../utilities/verification.utilities";
import type { Cache } from 'cache-manager';


export class TypeOrmResourceRepository<TUser extends BaseUser, TCreateDto = Partial<BaseUser>> 
implements ResourceRepositoryInterface<TUser, TCreateDto> {
    constructor(
        @Inject(AUTH_CONFIG_TOKEN) private readonly options: AuthModuleOptions,
        @Inject(MAILER) private readonly mailer: Mailer,
        private readonly model: Repository<any>,
        private readonly jwtService: JwtService,
        @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
    ) {}

    async create(data: TCreateDto, role?: string): Promise<TUser> {
        // get the role from the options
        const roleFromEntity = role || (data as any)?.role || this.options.defaultRole || 'user';

        // check if user 
        const itExist = await this.model.findOne({
            where: { email: (data as any)?.email }
        })

        // If user exist throw an error
        if (itExist) {
            throw new ConflictException(`User with email ${(data as any)?.email} already exist`)

        }

        // Hash user password
        const hashPasword = await this.hashPassword((data as any)?.password)

        // remove the password and the role from the data

        const { role: roleData, password, ...rest} = data as any;

        const newUser = this.model.create({
            ...rest,
            password: hashPasword,
            role: roleFromEntity,
        })
        // save the user
        const createdUser = await this.model.save(newUser);

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
            const subject = this.options.emailVerification?.subject || 'OTP Verification';
            if (!newUser.id || !newUser.email) {
                throw new NotFoundException(`User with email ${(data as any)?.email} does not have an email address`);
            }
            await verificationType.sendVerification(newUser, 
                { type: 'otp', purpose: 'email-verification', via: 'email' }, 
                this.options, this.cacheManager, subject
            );
        } else if (this.options.enableSms === true) {
            const subject = 'SMS OTP Verification';
            if (!newUser.id || !newUser.phone) {
                throw new NotFoundException(`User with phone ${(data as any)?.phone} does not exist`)
            }
            await verificationType.sendVerification(newUser,
                { type: 'sms-otp', purpose: 'sms-verification', via: 'sms' },
                this.options, this.cacheManager, subject
            )
        }

        // remove the password from the created User
        const userWithoutPassword = stripPassword(createdUser)
        // Return user created
        return userWithoutPassword
    }

    async findAll(): Promise<TUser[]> {
        const users = await this.model.find();

        // Remove password from each user
        const userWithoutPassword = users.map(user => {
            const { password, ...userWithoutPassword } = user;
            return userWithoutPassword;
        })

        return userWithoutPassword;
    }

    async findById(id: string | number): Promise<TUser> {
        const user = await this.model.findOne({
            where: { id }
        })

        if (!user) {
            throw new NotFoundException(`User with id ${id} not found`);
        }

        // Remove password from the user
        const userWithoutPassword = stripPassword(user);
        return userWithoutPassword;
    }

    async update(id: string | number, data: TCreateDto): Promise<TUser> {
        const user = await this.model.findOne({
            where: { id }
        });

        if (!user) {
            throw new NotFoundException(`User with id ${id} not found`);
        }

        // If password is provided, hash it
        if ((data as any)?.password) {
            (data as any).password = await this.hashPassword((data as any).password);
        }

        // Update the user
        const updatedUser = await this.model.save({
            ...user,
            ...data
        });

        // Remove password from the updated user
        const userWithoutPassword = stripPassword(updatedUser)
        return userWithoutPassword
    }

    async delete(id: string | number): Promise<{ message: string }> {
        const user = await this.model.findOne({
            where: { id }
        });

        if (!user) {
            throw new NotFoundException(`User with id ${id} not found`);
        }
        
        // Delete the user
        await this.model.delete(id);

        return { message: "user with "+ id + " was deleted successfully" }
    }

    async findByEmail(email: string | number): Promise<TUser> {
        const user = await this.model.findOne({
            where: { email }
        });

        if (!user) {
            throw new NotFoundException(`User with email ${email} not found`);
        }

        // Remove password from the user
        const userWithoutPassword = stripPassword(user)
        return userWithoutPassword
    }

    async findByUsername(username: string): Promise<TUser> {
        const user = await this.model.findOne({
            where: { username }
        });

        if (!user) {
            throw new NotFoundException(`User with username ${username} not found`);
        }

        // Remove password from the user
        const userWithoutPassword = stripPassword(user)
        return userWithoutPassword
    }

    async login(data: TCreateDto): Promise<any> {
        const user = await this.model.findOne({
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
            throw new NotFoundException(`Invalid password for user with email ${(data as any)?.email}`);
        }
        

        // remove password from the user
        const userWithoutPassword = stripPassword(user);

        // Generate tokens
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
                type: 'token', value: token, purpose: 'email-verification'}, this.options)
            
            if (!decoded) {
                throw new BadRequestException('Invalid verification token');
            }

            // Find the user by id
            const user = await this.findById(decoded);
            if (!user) {
                throw new NotFoundException(`User with id ${decoded} not found`);
            }

            // If user is already verified, throw an error
            if (user.verified) {
                throw new ConflictException(`User with email ${user.email} is already verified`);
            }

            // update the user to set verified to true
            user.verified = true;
            await this.model.save(user);
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

            const user = await this.model.findOne({
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
            await this.model.save(user);

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

    async verifyPhoneOtp(otp: string, phone: string): Promise<{ success: true, message: string }>{
        try {
            if (!otp || !phone) {
                    throw new BadRequestException('Phone and OTP are required for verification');
            }
    
            const verificationPhone = await verificationType.verify({
                type: 'sms-otp', value: otp, purpose: 'sms-verification', phone },
                this.options, this.cacheManager
            );
    
            const user = await this.model.findOne({
                where: { phone: verificationPhone }
            });
    
            if (!user) {
                throw new NotFoundException(`User with phone ${verificationPhone} not found`);
            }
    
            // If user is already verified, throw an error
            if (user.verified) {
                throw new ConflictException(`User with phone ${user.phone} is already verified`);
            }
    
            // update the user to set verified to true
            user.verified = true;
            await this.model.save(user)
    
            return {
                success: true,
                message: 'Phone number verified successfully'
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

    async resendPhoneOtp(phone: string): Promise<{ success: true; message: string; }> {
        // find user by phone number
        const user = await this.model.findOne({
            where: { phone }
        })

        if (!user) {
            throw new NotFoundException(`User with phone ${phone} not found`);
        }

        if (!user.id || !user.phone) {
            throw new NotFoundException(`User with phone ${phone} does not have a phone number`);
        }
        
        // send otp to user phone
        const subject = 'SMS OTP Verification';
        await verificationType.sendVerification(user, { type: 'sms-otp', purpose: 'sms-verification', via: 'sms' },
            this.options, this.cacheManager, subject
        )
        return { success: true, message: `OTP sent to ${phone}` };
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
            user.password = hashedPassword;
            const updatedUser = await this.model.save(user);
    
            // remove password from the updated user
            const userWithoutPassword = stripPassword(updatedUser);
            return userWithoutPassword;
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                throw new UnauthorizedException('Reset token has expired')
            } else if (error.name === 'JsonWebTokenError') {
                throw new UnauthorizedException('Invalid reset token');
            } else {
                throw new UnauthorizedException(`Token verification failed`);
            }
        }
    }
    
    async refreshToken(token: string): Promise<any>{
        try {
            // decode token and verify it
            const decoded = this.jwtService.verify(token, jwtVerifyOptions(this.options, 'refresh'));

            // check if the user exists
            const user = await this.findById(decoded.sub);

            if (!user) {
                throw new NotFoundException(`User with id ${decoded.sub} not found`);
            }

            // Generate new tokens
            const newTokens = this.generateToken(user);
            return { newTokens }
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

        await verificationType.sendVerification({ id: user.id, email: user.email }, 
            {type: 'token', purpose: 'password-reset', via: 'email'},
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
            const user = await this.model.findOne({
              where: { email: verificationEmail }
            });

            if (!user) {
               throw new NotFoundException(`User with email ${verificationEmail} not found`);
            }

            // Hash the new password
            const hashedPassword = await this.hashPassword(newPassword);
            // Update the user password
            user.password = hashedPassword;
            const updatedUser = await this.model.save(user);

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
            role: user.role
        }

        return this.jwtService.sign(payload, jwtSignOptions(this.options))
    }

    private generateRefreshToken(user: BaseUser): string {
        const payload = {
            email: user.email,
            sub: user.id,
            role: user.role
        }

        return this.jwtService.sign(payload, jwtRefreshSignOptions(this.options))
    }

    private async hashPassword(password: string): Promise<string> {
        return bcrypt.hash(password, 10);
    }

    private async verifyHashPassword(plainPassword: string, hashPasword: string): Promise<boolean> {
        return await bcrypt.compare(plainPassword, hashPasword);
    }
}