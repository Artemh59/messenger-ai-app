import { Body, Controller, Get, UseGuards, Req, Post, Res } from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

const REFRESH_COOKIE_NAME = process.env.REFRESH_COOKIE_NAME ?? 'refresh_token';
const COOKIE_OPTIONS = {
	httpOnly: true,
	secure: process.env.NODE_ENV === 'production',
	sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
	path: '/',
} as const;

@Controller('auth')
export class AuthController {
	constructor(private auth: AuthService) {}

	@Post('register')
	async register(@Body() dto: RegisterDto, @Res({ passthrough: true }) res: Response) {
		const { accessToken, refreshToken, refreshExpiresAt } = await this.auth.register(
			dto.username,
			dto.password,
		);
		res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
			...COOKIE_OPTIONS,
			expires: refreshExpiresAt,
		});
		return { accessToken };
	}

	@Post('login')
	async login(@Body() dto: LoginDto, @Res({ passthrough: true }) res: Response) {
		const { accessToken, refreshToken, refreshExpiresAt } = await this.auth.login(
			dto.username,
			dto.password,
		);
		res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
			...COOKIE_OPTIONS,
			expires: refreshExpiresAt,
		});
		return { accessToken };
	}

	@Post('refresh')
	async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
		const token = req.cookies?.[REFRESH_COOKIE_NAME];
		const { accessToken, refreshToken, refreshExpiresAt } = await this.auth.refresh(token);
		res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
			...COOKIE_OPTIONS,
			expires: refreshExpiresAt,
		});
		return { accessToken };
	}

	@Post('logout')
	async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
		const token = req.cookies?.[REFRESH_COOKIE_NAME];
		await this.auth.logout(token);
		res.clearCookie(REFRESH_COOKIE_NAME, COOKIE_OPTIONS);
		return { ok: true };
	}

	@UseGuards(AuthGuard('jwt'))
	@Get('me')
	me(@Req() req: Request) {
		return req.user;
	}
}
