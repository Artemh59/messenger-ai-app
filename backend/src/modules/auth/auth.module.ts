import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RefreshTokenService } from './refresh-token.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    UsersModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => ({
        secret: config.get('JWT_ACCESS_SECRET'),
        signOptions: {
          expiresIn: config.get('JWT_ACCESS_TTL'),
        },
      }),
      inject: [ConfigService],
    })],
  controllers: [AuthController],
  providers: [AuthService, RefreshTokenService, JwtStrategy]
})
export class AuthModule {}
