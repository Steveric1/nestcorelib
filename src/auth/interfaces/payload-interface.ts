import { BaseUser } from "./base-user.interface";


export interface Payload extends BaseUser {
    sub: string | number; // User ID
    iat?: number; // Issued at
    exp?: number; // Expiration time
    iss?: string; // Issuer
    aud?: string; // Audience
    roles?: string[]; // User roles
    permissions?: string[]; // User permissions
}