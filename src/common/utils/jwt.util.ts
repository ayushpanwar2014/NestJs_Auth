import * as jwt from 'jsonwebtoken';

export class JwtUtil {
    static signAccessToken(payload: object): string {
        return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
            expiresIn: '15m',
        });
    }

    static signRefreshToken(payload: object): string {
        return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {
            expiresIn: '7d',
        });
    }

    static verifyAccessToken(token: string) {
        return jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    }

    static verifyRefreshToken(token: string) {
        return jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    }

    static decode(token: string) {
        return jwt.decode(token);
    }
}