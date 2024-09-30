import { BadRequestException, Injectable } from '@nestjs/common';
import { UsersService } from 'src/modules/users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService
  ) {}

  async signup(email: string, password: string) {
    const users = await this.usersService.find(email);
    if (users.length) {
      throw new BadRequestException('Email already in use');
    }

    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);
    return this.usersService.create(email, hashedPassword);
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

    const payload = { email: user.email, sub: user.id };
    const access_token = await this.jwtService.signAsync(payload, {
      expiresIn: '15m',
    });

    const refresh_token = await this.jwtService.signAsync(payload, {
      expiresIn: '30d',
    });

    user.refreshToken = refresh_token;
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
}
