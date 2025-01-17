import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersModule } from 'src/modules/users/users.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthGuard } from 'src/common/guards/auth.guard';
import { User } from '../users/user.entity';

@Module({
  imports: [
    UsersModule,
    TypeOrmModule.forFeature([User]),
    JwtModule.registerAsync(
      AuthModule.createJwtModuleOptions(
        'JWT_ACCESS_SECRET',
        'JWT_ACCESS_EXPIRATION'
      )
    ),
    JwtModule.registerAsync(
      AuthModule.createJwtModuleOptions(
        'JWT_REFRESH_SECRET',
        'JWT_REFRESH_EXPIRATION'
      )
    ),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    UsersService,
    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
  ],
})
export class AuthModule {
  protected static createJwtModuleOptions(
    secretKey: string,
    expirationKey: string
  ) {
    return {
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>(secretKey),
        signOptions: {
          expiresIn: configService.get<string>(expirationKey),
        },
      }),
    };
  }
}
