import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as argon2 from 'argon2';

@Injectable()
export class AuthService {
	constructor( 
		private users: UsersService,
		private jwt: JwtService,
	) {}

	async register(username: string, password: string) {
		const passwordHash = await argon2.hash(password);

		return this.users.createUser({
			username,
			passwordHash
		});
	}

	async login(username: string, password: string) {
		const user = await this.users.findByUsername(username);

		if (!user) {
			throw new UnauthorizedException();
		}

		const valid = await argon2.verify(user.passwordHash, password);

		if (!user) {
			throw new UnauthorizedException();
		}

		const accessToken = this.jwt.sign({
			sub: user.id,
			username: user.username,
		});

		return { accessToken }
	}
}
