import { IsEmail, IsNotEmpty, IsString, MinLength } from "class-validator";


export class LoginDto {
    @IsNotEmpty({ message: "Password cannot be empty" })
    @MinLength(6, { message: "Password must be at least 6 character long" })
    password: string;
}