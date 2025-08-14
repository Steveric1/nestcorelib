import { Inject, Logger } from "@nestjs/common";
import { SmsSender } from "../interfaces/mail-sms.interface";
import { AUTH_CONFIG_TOKEN, AuthModuleOptions } from "../interfaces/auth-module-options.interface";


export class CorelibSmsSender implements SmsSender {
    private readonly logger = new Logger(CorelibSmsSender.name);

    constructor(@Inject(AUTH_CONFIG_TOKEN) private readonly options: AuthModuleOptions) {
        if (!this.options.enableSms) {
            this.logger.warn('SMS sending is disabled in the configuration. Please enable it to use SMS features.');
        } else {
            this.logger.log(`SMS is enabled using provider: ${this.options.smsVerification?.provider || 'custom'}`);
        }
    }

    async sendSms(to: string, message: string): Promise<void> {
        const smsConfig = this.options.smsVerification;
        if (!smsConfig) {
            this.logger.warn('SMS configuration is not provided.');
        }

        // 1. Use custom sender if provided
        if (smsConfig?.provider === 'custom' && smsConfig.customSender) {
            try {
                await smsConfig.customSender(to, message);
                this.logger.log(`SMS sent to ${to} using custom sender.`);
                return; // stop here if successful
            } catch (error) {
                this.logger.error(`Failed to send SMS to ${to} using custom sender.`, error);
            }
        }

        // 2. Use Twilio if configured
        if (smsConfig?.provider === 'twilio') {
            const twilio = require('twilio')(smsConfig.apiKey, smsConfig.apiSecret);
            try {
                await twilio.messages.create({
                    body: message,
                    from: smsConfig.from || smsConfig.senderId,
                    to: to
                })
                this.logger.log(`SMS sent to ${to} using Twilio.`);
                return; // stop here if successful
            } catch (error) {
                this.logger.error(`Failed to send SMS to ${to} using Twilio.`, error);
            }
        }

        // 3. Use Vonage if configured
        // if (smsConfig?.provider === 'vonage') {
        //     const vonage = require('@vonage/server-sdk')({
        //         apiKey: smsConfig.apiKey,
        //         apiSecret: smsConfig.apiSecret
        //     })
        //     try {
        //         await vonage.message.sendSms({

        //             from: smsConfig.from || smsConfig.senderId,
        //             to: to,
        //             text: message
        //         })
        //     } catch (error) {
        //         this.logger.error(`Failed to send SMS to ${to} using Vonage.`, error);
        //     }
        // }

        throw new Error('No valid SMS provider configured or failed to send SMS.');
    }
}