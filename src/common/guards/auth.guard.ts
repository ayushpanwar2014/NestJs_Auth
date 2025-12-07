import {
    CanActivate,
    ExecutionContext,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Session, SessionDocument } from 'src/database/schema/session.schema';
import { JwtUtil } from '../utils/jwt.util';
import { CookieUtil } from '../utils/cookie.util';

@Injectable()
export class AuthGuard implements CanActivate {
    constructor(
        @InjectModel(Session.name) private sessionModel: Model<SessionDocument>,
    ) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const req: any = context.switchToHttp().getRequest();
        const res: any = context.switchToHttp().getResponse();

        const accessToken = req.cookies?.access_token;
        const refreshToken = req.cookies?.refresh_token;

        req.user = null;

        // PUBLIC ROUTE
        if (!accessToken && !refreshToken) {
            throw new UnauthorizedException("Not Logged In");
        }
        if (accessToken && !refreshToken) {
            try {
                const decoded: any = JwtUtil.verifyAccessToken(accessToken);
                await this.sessionModel.findByIdAndDelete(decoded.sessionID);
            } catch { }
            res.clearCookie('access_token');
            return true;
        }

        try {
            const decodedRefresh: any = JwtUtil.verifyRefreshToken(refreshToken);
            const session = await this.sessionModel.findById(decodedRefresh.sessionID);

            if (!session) {
                res.clearCookie('access_token');
                res.clearCookie('refresh_token');
                return true;
            }
        } catch {
            throw new UnauthorizedException('Invalid refresh token');
        }

        if (accessToken) {
            try {
                const decodedAccess = JwtUtil.verifyAccessToken(accessToken);
                req.user = decodedAccess;
                return true;
            } catch (err) {
                // Access token expired → try refresh flow
                if (err.name === 'TokenExpiredError' && refreshToken) {
                    return await this.handleRefresh(req, res, refreshToken);
                }
                throw new UnauthorizedException('Invalid access token');
            }
        }

        if (refreshToken) {
            return await this.handleRefresh(req, res, refreshToken);
        }

        throw new UnauthorizedException('Unauthorized');
    }

    //  REFRESH TOKEN FLOW
    private async handleRefresh(req: any, res: any, refreshToken: string) {
        let decodedRefresh: any;

        try {
            decodedRefresh = JwtUtil.verifyRefreshToken(refreshToken);
        } catch {
            throw new UnauthorizedException('Invalid refresh token');
        }

        const oldSession = await this.sessionModel.findById(decodedRefresh.sessionID);

        if (!oldSession) {
            res.clearCookie('access_token');
            res.clearCookie('refresh_token');
            return false;
        }

        // Delete old session
        await this.sessionModel.findByIdAndDelete(oldSession._id);

        // Create new session
        const newSession = await this.sessionModel.create({
            userId: oldSession.userId,
            userAgent: req.headers['user-agent'] || 'unknown',
            ip: req.ip || req.connection.remoteAddress,
            expiresAt: new Date(Date.now() + 7 * 86400000),
        });

        // Generate new tokens
        const newAccessToken = JwtUtil.signAccessToken({
            userId: oldSession.userId,
            sessionID: newSession._id,
        });

        const newRefreshToken = JwtUtil.signRefreshToken({
            sessionID: newSession._id,
        });

        // Set cookies
        const accessCookie = CookieUtil.accessTokenCookie(newAccessToken);
        const refreshCookie = CookieUtil.refreshTokenCookie(newRefreshToken);

        res.cookie(accessCookie.name, accessCookie.value, accessCookie.options);
        res.cookie(refreshCookie.name, refreshCookie.value, refreshCookie.options);

        // Attach user to req
        req.user = {
            userId: oldSession.userId,
            sessionID: newSession._id,
        };

        return true;
    }
}