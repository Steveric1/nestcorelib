

export interface Mailer {
    sendMail(to: string, subject?: string, html?: string): Promise<void>;
}

export interface SmsSender {
    sendSms(to: string, message: string): Promise<void>;
}

export const MAILER = Symbol('MAILER');
export const SMS_SENDER = Symbol('SMS_SENDER');

export type verificationType = 'token' | 'otp' | 'sms-otp';
export type verificationPurpose = 'email-verification' | 'password-reset' | 'two-factor-authentication' | 'sms-verification';
export type verificationVia = 'email' | 'sms';

export interface SendVerificationOptions {
    type: verificationType;
    purpose: verificationPurpose;
    via: verificationVia;
    expiresIn?: string;
}

export interface verifyIput {
    type: verificationType;
    value: string;
    purpose: string;
    email?: string;
    phone?: string;
}