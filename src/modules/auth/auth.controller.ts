import { Body, Controller, Get, Post, Req, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import type { Response } from 'express';
import { AuthGuard } from 'src/common/guards/auth.guard';

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
        @Req() req: any
    ) {
        return this.authService.login(dto, res, req);
    }

    @Post('logout')
    async logout(@Req() req: any, @Res({ passthrough: true }) res: Response) {
        return this.authService.logout(req, res);
    }

    // PROTECTED
    @UseGuards(AuthGuard)
    @Get('get-user')
    getMe(@Req() req: any) {
        return this.authService.getMe(req);
    }
}