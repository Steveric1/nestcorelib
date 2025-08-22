import { BadRequestException } from "@nestjs/common";
import { SendVerificationOptions, verifyIput } from "../interfaces/mail-sms.interface";
import { signWitDynamicKey, verifyWithDynamicKey } from "./auth.jwt";
import { AuthModuleOptions } from "../interfaces/auth-module-options.interface";
import { DefaultMailer } from "../mail-and-sms/send.mail";
import { BaseUser } from "../interfaces/base-user.interface";
import { CorelibSmsSender } from "../mail-and-sms/send.sms";




export const verificationType = {
    async sendVerification(
        user: BaseUser, 
        opts: SendVerificationOptions, 
        options: AuthModuleOptions,
        cache: any,
        subject: string): Promise<void> {
        const { type, purpose, via } = opts;

        // check type 
        if (type === 'token') {
            const token = signWitDynamicKey(
                { sub: String(user.id), purpose },
                options
            )
            console.log(token);
            const html = options.emailVerification?.htmlBuilder
                ? options.emailVerification?.htmlBuilder(token, user) 
                : `<p>Click link to verify your email: <a href="http://localhost:3000/verify-email?token=${token}">Verify Email</a></p>`;

            // const link = `http://localhost:3000/reset-password?token=${token}`
            if (!user.email) {
                throw new BadRequestException('User email is required for verification');
            }
            await new DefaultMailer(options).sendMail(user.email, subject, html);
        } else if (type === 'otp') {
            // generat otp
            const otp = this.generateOtp();
            console.log('Generated OTP:', otp);
            // set key
            const key = this.otpKey(user.email, purpose);
            // set otp in cache
            await cache.set(key, otp, { ttl: 60 * 5 }); // 5 minutes
            const html= options.emailVerification?.htmlBuilder
                ? options.emailVerification?.htmlBuilder(otp, user)
                : `<p>Your OTP for verification is: <strong>${otp}</strong></p>`;

            if (!user.email) {
                throw new BadRequestException('User email is required for verification');
            }
            await new DefaultMailer(options).sendMail(user.email, subject, html);

        } else if (type === 'sms-otp') {
            // generate otp
            const otp = this.generateOtp();
            console.log('Generated SMS OTP:', otp);
            // set key
            const key = this.otpKey(user.phone, purpose);
            // set otp in cache
            await cache.set(key, otp, { ttl: 60 * 5}); // 5 minutes
            if (!user.phone) {
                throw new BadRequestException('User phone number is required for verification');
            }

            subject = options.smsVerification?.message ? options.smsVerification.message(otp) 
            : `Your OTP for verification is: ${otp}`;

            await new CorelibSmsSender(options).sendSms(user.phone, subject);
        } else {
            throw new BadRequestException('Invalid verification type');
        }
    },

    async verify (input: verifyIput, options: AuthModuleOptions, cache?: any) {
        const { type, value, purpose, email, phone } = input;

        // check type
        if (type === 'token') {
            // verify token
            const decoded = verifyWithDynamicKey(value, options);
            if (decoded.purpose !== purpose) throw new BadRequestException('Invalid token purpose');
            return String(decoded.sub);
        }

        if (type === 'otp') {
            // check if the user has an email
            if (!email) throw new BadRequestException('User email is required for verification');

            // get key
            const key = this.otpKey(email, purpose);
            const cachedOtp = await cache.get(key);
            if (!cachedOtp) {
                throw new BadRequestException('OTP has expired or does not exist');
            }

            if (cachedOtp !== value) {
                throw new BadRequestException('Invalid OTP');
            }

            // delete otp from cache
            await cache.del(key);
            return email; // return email as the user identifier
        } else if (type === 'sms-otp') {
            // Check if the user has a phone number
            if (!phone) throw new BadRequestException('User phone number is required for verification');

            // get key 
            const key = this.otpKey(phone, purpose)
            const cachedOtp = await cache.get(key);
            if (!cachedOtp) throw new BadRequestException('OTP has expired or does not exist');

            if (cachedOtp !== value) throw new BadRequestException('Invalid OTP');

            // delete otp from cache
            await cache.del(key);
            return phone;
        }
    },

    generateOtp(length: number = 6): string {
        return Math.floor(100000 + Math.random() * 900000).toString().slice(0, length);
    },

    otpKey(email: string, purpose: string): string {
        return `otp:${email}:${purpose}`;
    }
}