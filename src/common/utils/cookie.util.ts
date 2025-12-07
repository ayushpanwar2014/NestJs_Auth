export class CookieUtil {
    static accessTokenCookie(token: string) {
        return {
            name: 'access_token',
            value: token,
            options: {
                httpOnly: true,
                secure: false,               // false if localhost on http
                sameSite: 'lax' as const,
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
                secure: false,
                sameSite: 'lax' as const,  // FIXED
                path: '/',
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            },
        };
    }

    static clearAuthCookies() {
        return [
            { name: 'access_token', options: { path: '/', sameSite: 'lax' as const } },
            { name: 'refresh_token', options: { path: '/', sameSite: 'lax' as const } },
        ];
    }
}