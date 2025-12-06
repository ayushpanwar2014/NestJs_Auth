import { Body, Controller, Get, Post, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import type { AuthenticatedRequest } from 'src/common/middleware/auth.middleware';
import type { Response } from 'express';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Post('register')
    async register(@Body() dto: RegisterDto) {
        return this.authService.register(dto);
    }

    @Post('login')
    async login(
        @Body() dto: LoginDto,
        @Res({ passthrough: true }) res: Response,
    ) {
        // Service will handle: validate user, create session, set cookies
        return this.authService.login(dto, res);
    }

    @Post('logout')
    async logout(@Req() req: AuthenticatedRequest, @Res({ passthrough: true }) res: Response) {
        return this.authService.logout(req, res);
    }

    @Get('me')
    async getMe(@Req() req: AuthenticatedRequest) {
        return this.authService.getMe(req);
    }
}
