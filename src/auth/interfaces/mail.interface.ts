

export interface Mailer {
    sendMail(to: string, token?: string): Promise<void>;
}

export const MAILER = Symbol('MAILER');

export type verificationType = 'token' | 'otp';
export type verificationPurpose = 'email-verification' | 'password-reset';
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
}