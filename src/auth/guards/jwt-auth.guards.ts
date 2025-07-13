import { AuthGuard } from "@nestjs/passport";


export class AccessGuard extends AuthGuard('access-jwt'){}
export class RefreshGuard extends AuthGuard('refresh-jwt') {}
