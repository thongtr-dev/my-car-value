import { BadRequestException, Injectable } from '@nestjs/common';
import { UsersService } from '../users.service';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
  constructor(private readonly usersService: UsersService) {}

  async signup(email: string, password: string) {
    const users = await this.usersService.find(email);
    if (users.length) {
      throw new BadRequestException('Email already in use');
    }

    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);
    return this.usersService.create(email, hashedPassword);
  }
  signin() {}
}
