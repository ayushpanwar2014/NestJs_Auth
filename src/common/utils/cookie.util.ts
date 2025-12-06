export class CookieUtil {
    static accessTokenCookie(token: string) {
        return {
            name: 'access_token',
            value: token,
            options: {
                httpOnly: true,
                secure: true,               // false if localhost on http
                sameSite: 'strict' as const,
                path: '/',
                maxAge: 15 * 60 * 1000,     // 15 min
            },
        };
    }

    static refreshTokenCookie(token: string) {
        return {
            name: 'refresh_token',
            value: token,
            options: {
                httpOnly: true,
                secure: true,
                sameSite: 'strict' as const,  // FIXED
                path: '/',
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            },
        };
    }

    static clearAuthCookies() {
        return [
            { name: 'access_token', options: { path: '/', sameSite: 'strict' as const } },
            { name: 'refresh_token', options: { path: '/', sameSite: 'strict' as const } },
        ];
    }
}