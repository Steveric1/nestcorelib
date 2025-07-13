import { AUTH_CONFIG_TOKEN, AuthModuleOptions } from "../interfaces/auth-module-options.interface";
import { Mailer } from "../interfaces/mail.interface";
import * as nodeMailer from "nodemailer";
import { Inject, Logger, OnModuleInit } from "@nestjs/common";



export class DefaultMailer implements Mailer, OnModuleInit {
    private transporter: nodeMailer.Transporter;
    private isEthereal: boolean = false;
    private readonly logger = new Logger(DefaultMailer.name);

    constructor(@Inject(AUTH_CONFIG_TOKEN) private readonly options: AuthModuleOptions) {}

    async onModuleInit() {
        // Ensure transporter is initialized when the module is initialized
        await this.initTransporter();
    }

    private async initTransporter() {
        if (this.options.mailer?.host && this.options.mailer?.port && this.options.mailer?.user && this.options.mailer?.pass) {
            // Use SMTP configuration
            this.transporter = nodeMailer.createTransport({
                host: this.options.mailer?.host,
                port: this.options.mailer?.port,
                secure: false,
                auth: {
                    user: this.options.mailer?.user,
                    pass: this.options.mailer?.pass
                },
            });
        } else {
            // Fallback to ethreal
            const testAccount = await nodeMailer.createTestAccount();
            this.transporter = nodeMailer.createTransport({
                host: testAccount.smtp.host,
                port: testAccount.smtp.port,
                secure: testAccount.smtp.secure,
                auth: {
                    user: testAccount.user,
                    pass: testAccount.pass
                },
            });

            this.isEthereal = true;
            this.logger.log('Using Ethereal Mailer');

            this.logger.log(`Using Ethereal Mailer: ${testAccount.user}:${testAccount.pass}`);
            this.logger.log(`Email sent to: ${testAccount.smtp.host}:${testAccount.smtp.port}`);
            this.logger.log('Login: https://ethereal.email/login')
        }
    }

    async sendMail(to: string, subject?: string,  html?: string): Promise<void> {
        if (!this.transporter) {
            // Ensure transporter is initialized
            await this.initTransporter()
        }

        const info = await this.transporter.sendMail({
            from: this.options.mailer?.from ||  'no-reply@yourapp.com',
            to,
            subject: subject,
            html: html,
        });

        if (this.isEthereal) {
            this.logger.log(`Preview URL: ${nodeMailer.getTestMessageUrl(info)}`);
        } else {
            this.logger.log(`Email sent successfully to ${to}`);
        }
    }
}