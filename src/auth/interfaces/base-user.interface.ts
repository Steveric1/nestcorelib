

export interface BaseUser {
    id?: string | number;
    email?: string;
    password?: string;
    username?: string;
    role?: string | null;
    verified?: boolean;
}

// Define safe user type to omit password
// export type SafeUser<T extends BaseUser> = Omit<T, 'password'>;
