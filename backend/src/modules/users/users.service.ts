import { Injectable } from "@nestjs/common";
import { PrismaService } from "../../modules/prisma/prisma.service";

@Injectable()
export class UsersService {
	constructor(private readonly prisma: PrismaService) {}

	findById(id: string) {
		return this.prisma.user.findUnique({
			where: { id }
		})
	}

	findByUsername(username: string) {
		return this.prisma.user.findUnique({
			where: { username }
		})
	}

	createUser(args: { username: string, passwordHash: string }) {
		const { username, passwordHash } = args;

		return this.prisma.user.create({
			data: {
				username,
				passwordHash
			}
		})
	}
}
