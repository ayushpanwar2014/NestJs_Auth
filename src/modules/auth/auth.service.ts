// src/modules/auth/auth.service.ts
import { ConflictException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Response } from 'express';
import { AuthenticatedRequest } from '../../common/middleware/auth.middleware';
import { User, UserDocument } from 'src/database/schema/user.schema';
import { Session, SessionDocument } from 'src/database/schema/session.schema';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { PasswordUtil } from 'src/common/utils/password.util';
import { JwtUtil } from 'src/common/utils/jwt.util';
import { CookieUtil } from 'src/common/utils/cookie.util';

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(User.name) private userModel: Model<UserDocument>,
        @InjectModel(Session.name) private sessionModel: Model<SessionDocument>,
    ) { }

    async register(dto: RegisterDto) {
        const exists = await this.userModel.findOne({ email: dto.email });
        if (exists) throw new ConflictException('Email already exists');

        const hashedPassword = await PasswordUtil.hash(dto.password);

        const user = await this.userModel.create({
            name: dto.name,
            email: dto.email,
            password: hashedPassword,
        });

        return {
            success: true,
            message: 'User registered successfully',
            userId: user._id,
        };
    }

    async login(dto: LoginDto, res: Response, req: any) {
        
        const user = await this.userModel.findOne({ email: dto.email });
        if (!user) throw new NotFoundException('Invalid credentials');

        const validPassword = await PasswordUtil.verify(user.password, dto.password);
        if (!validPassword) throw new UnauthorizedException('Invalid credentials');

        // 2) Create a session (store refresh token in DB)
        const session = await this.sessionModel.create({
            userId: user._id,
            userAgent: req.headers['user-agent'] || 'unknown', // browser
            ip: req.ip || req.connection.remoteAddress, // IP address
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days expiry
        });

        // Create tokens
        const accessToken = JwtUtil.signAccessToken({
            userId: user._id,
            sessionID: session._id,
        });

        const refreshToken = JwtUtil.signRefreshToken({
            sessionID: session._id,
        });

        const accessCookie = CookieUtil.accessTokenCookie(accessToken);
        const refreshCookie = CookieUtil.refreshTokenCookie(refreshToken);

        res.cookie(accessCookie.name, accessCookie.value, accessCookie.options);
        res.cookie(refreshCookie.name, refreshCookie.value, refreshCookie.options);

        return {
            success: true,
            message: 'Login successful',
        };
    }

    async logout(req: AuthenticatedRequest, res: Response) {
        // TODO:
        // 1) delete session from DB (if you store sessionId / refresh token mapping)
        // 2) clear cookies
        res.clearCookie('access_token');
        res.clearCookie('refresh_token');
        return { success: true };
    }

    async getMe(req: AuthenticatedRequest) {
        // TODO: return user based on req.user or tokens
        return { user: req.user || null };
    }
}