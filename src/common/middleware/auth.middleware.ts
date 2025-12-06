import { Injectable, NestMiddleware, UnauthorizedException } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

export interface AuthenticatedRequest extends Request {
    user?: any;
    accessToken?: string;
    refreshToken?: string;
}

@Injectable()
export class AuthMiddleware implements NestMiddleware {
    async use(req: AuthenticatedRequest, res: Response, next: NextFunction) {
        const accessToken = req.cookies?.access_token;
        const refreshToken = req.cookies?.refresh_token;

        req.accessToken = accessToken;
        req.refreshToken = refreshToken;

        // ⬇️ Here is where YOU can put your verify/decode logic
        // Example idea (you'll implement):
        //
        // if (accessToken) {
        //   const payload = verifyToken(accessToken, process.env.JWT_SECRET);
        //   req.user = payload;
        // } else if (refreshToken) {
        //   const payload = verifyToken(refreshToken, process.env.JWT_SECRET);
        //   req.user = payload;
        // }
        //
        // If no valid token and route is protected -> throw UnauthorizedException

        // For now, just continue:
        return next();
    }
}
