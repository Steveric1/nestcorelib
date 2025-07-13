import { IsEmail, IsNotEmpty, IsOptional, IsString, MinLength } from "class-validator";


export class RegisterDto {
    @IsEmail({}, { message: "Please provide a valid email address" })
    @IsString({ message: "Email must be a string" })
    email: string;

    @IsNotEmpty({ message: "Password cannot be empty" })
    @MinLength(6, { message: "Password must be at least 6 character long" })
    password: string;

    @IsOptional()
    @IsString({ message: "Field is expected to be string" })
    fullName?: string
}