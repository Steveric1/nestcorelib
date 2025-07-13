

export function stripPassword(user: any) {
    const { password, ...rest} = user;
    return rest
}