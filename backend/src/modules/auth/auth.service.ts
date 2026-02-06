import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as argon2 from 'argon2';
import { User } from '@prisma/client';
import { RefreshTokenService } from './refresh-token.service';
import type { SignOptions } from 'jsonwebtoken';


@Injectable()
export class AuthService {
	constructor(
		private users: UsersService,
		private jwt: JwtService,
		private refreshTokens: RefreshTokenService,
	) {}

	private signAccess(user: User) {
		return this.jwt.sign({
			sub: user.id,
			username: user.username,
		});
	}

	private signRefresh(user: User) {
		const payload = { sub: user.id };
		return this.jwt.sign<typeof payload>(payload, {
			secret: process.env.JWT_REFRESH_SECRET,
			expiresIn: process.env.JWT_REFRESH_TTL as SignOptions['expiresIn'],
		});
	}

	private getTokenExpiry(token: string) {
		const payload = this.jwt.decode(token) as { exp?: number } | null;
		if (!payload?.exp) {
			throw new UnauthorizedException();
		}
		return new Date(payload.exp * 1000);
	}

	private async issueTokens(user: User) {
		const accessToken = this.signAccess(user);
		const refreshToken = this.signRefresh(user);
		const refreshExpiresAt = this.getTokenExpiry(refreshToken);

		await this.refreshTokens.create(user.id, refreshToken, refreshExpiresAt);

		return { accessToken, refreshToken, refreshExpiresAt };
	}

	async register(username: string, password: string) {
		const passwordHash = await argon2.hash(password);
		const user = await this.users.createUser({
			username,
			passwordHash,
		});

		return this.issueTokens(user);
	}

	async login(username: string, password: string) {
		const user = await this.users.findByUsername(username);

		if (!user) {
			throw new UnauthorizedException();
		}

		const valid = await argon2.verify(user.passwordHash, password);
		if (!valid) {
			throw new UnauthorizedException();
		}

		return this.issueTokens(user);
	}

	async refresh(refreshToken?: string) {
		if (!refreshToken) {
			throw new UnauthorizedException();
		}
	
		let payload: { sub: string };
		try {
			payload = this.jwt.verify<{ sub: string }>(refreshToken, {
				secret: process.env.JWT_REFRESH_SECRET,
			});
		} catch {
			throw new UnauthorizedException();
		}
	
		if (!payload?.sub) {
			throw new UnauthorizedException();
		}
	
		const record = await this.refreshTokens.find(refreshToken);
		if (!record || record.revokedAt) {
			throw new UnauthorizedException();
		}
		if (record.expiresAt < new Date()) {
			throw new UnauthorizedException();
		}
	
		const user = await this.users.findById(payload.sub);
		if (!user) {
			throw new UnauthorizedException();
		}
	
		await this.refreshTokens.revoke(record.id);
	
		return this.issueTokens(user);
	}

	async logout(refreshToken?: string) {
		if (!refreshToken) return;

		const record = await this.refreshTokens.find(refreshToken);
		if (record && !record.revokedAt) {
			await this.refreshTokens.revoke(record.id);
		}
	}
}
