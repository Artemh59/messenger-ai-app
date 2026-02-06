import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import crypto from 'crypto';

@Injectable()
export class RefreshTokenService {
  constructor(private prisma: PrismaService) {}

  hash(token: string) {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  async create(userId: string, token: string, expiresAt: Date) {
    return this.prisma.refreshToken.create({
      data: {
        userId,
        tokenHash: this.hash(token),
        expiresAt,
      },
    });
  }

  async find(token: string) {
    return this.prisma.refreshToken.findUnique({
      where: { tokenHash: this.hash(token) },
    });
  }

  async revoke(id: string) {
    return this.prisma.refreshToken.update({
      where: { id },
      data: { revokedAt: new Date() },
    });
  }
}
