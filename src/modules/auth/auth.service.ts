import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from 'src/modules/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { TokenType } from 'src/common/enums/tokenType.enum';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService
  ) {}

  async signup(email: string, password: string) {
    const users = await this.usersService.find(email);
    if (users.length) {
      throw new BadRequestException('Email already in use');
    }

    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);
    await this.usersService.create(email, hashedPassword);

    return { message: 'User created successfully' };
  }

  async signin(email: string, password: string) {
    const [user] = await this.usersService.find(email);
    if (!user) {
      throw new BadRequestException('Invalid email or password');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new BadRequestException('Invalid email or password');
    }

    const access_token = await this.generateToken(
      TokenType.ACCESS,
      user.id,
      user.email
    );

    const refresh_token = await this.generateToken(
      TokenType.REFRESH,
      user.id,
      user.email
    );

    const hashedRefreshToken = await bcrypt.hash(refresh_token, 10);
    user.refreshToken = hashedRefreshToken;
    user.refreshTokenExpiration =
      Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60; // 30 days
    await this.usersService.update(user.id, user);

    return {
      id: user.id,
      email: user.email,
      access_token,
      refresh_token,
    };
  }

  async refreshTokens(userId: number, refresh_token: string) {
    const user = await this.usersService.findOne(userId);

    if (!user) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const isMatch = await bcrypt.compare(refresh_token, user.refreshToken);
    if (!isMatch) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const now = Math.floor(Date.now() / 1000);
    if (user.refreshTokenExpiration <= now) {
      throw new UnauthorizedException('Refresh token has expired');
    }

    const newRefreshToken = await this.generateToken(
      TokenType.REFRESH,
      user.id,
      user.email
    );

    const newAccessToken = await this.generateToken(
      TokenType.ACCESS,
      user.id,
      user.email
    );

    const hashedNewRefreshToken = await bcrypt.hash(newRefreshToken, 10);
    user.refreshToken = hashedNewRefreshToken;
    await this.usersService.update(user.id, user);

    return {
      id: user.id,
      email: user.email,
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
    };
  }

  async logout(userId: number) {
    const user = await this.usersService.findOne(userId);

    if (!user) {
      throw new BadRequestException('User not found');
    }

    // Clear refresh token and expiration
    user.refreshToken = null;
    user.refreshTokenExpiration = null;

    await this.usersService.update(user.id, user);

    return { message: 'Logged out successfully' };
  }

  private generateToken(tokenType: string, userId: number, email: string) {
    const payload = { sub: userId, email };
    switch (tokenType) {
      case TokenType.ACCESS:
        return this.jwtService.signAsync(payload, {
          expiresIn: this.configService.get<string>('JWT_ACCESS_EXPIRATION'),
        });
      case TokenType.REFRESH:
        return this.jwtService.signAsync(payload, {
          expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRATION'),
        });
      default:
        break;
    }
  }
}
