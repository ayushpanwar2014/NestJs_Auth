// src/modules/auth/auth.service.ts
import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Response } from 'express';
import { AuthenticatedRequest } from '../../common/middleware/auth.middleware';
import { User, UserDocument } from 'src/database/schema/user.schema';
import { Session, SessionDocument } from 'src/database/schema/session.schema';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(User.name) private userModel: Model<UserDocument>,
        @InjectModel(Session.name) private sessionModel: Model<SessionDocument>,
    ) { }

    async register(dto: RegisterDto) {
        // TODO: hash password, save user
        return { success: true };
    }

    async login(dto: LoginDto, res: Response) {
        // TODO:
        // 1) verify user + password
        // 2) create tokens (access + refresh)
        // 3) create session document
        // 4) set cookies on `res`
        return { success: true };
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
