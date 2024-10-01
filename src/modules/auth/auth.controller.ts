import {
  Body,
  Post,
  Controller,
  HttpCode,
  HttpStatus,
  Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Serialize } from 'src/common/interceptors/serialize.interceptor';
import { Public } from 'src/common/decorators/public.decorator';
import { AuthResponseDto } from 'src/common/dtos/auth-response.dto';
import { CreateUserDto } from 'src/common/dtos/create-user.dto';
import { RefreshTokenDTO } from './dtos/refresh-token.dto';
import { GetUser } from 'src/common/decorators/get-user.decorator';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('/signup')
  createUser(@Body() body: CreateUserDto) {
    return this.authService.signup(body.email, body.password);
  }

  @Public()
  @Post('/signin')
  @HttpCode(HttpStatus.OK)
  @Serialize(AuthResponseDto)
  signin(@Body() body: CreateUserDto) {
    return this.authService.signin(body.email, body.password);
  }

  @Public()
  @Post('/refresh-tokens')
  @Serialize(AuthResponseDto)
  refreshTokens(@Body() body: RefreshTokenDTO) {
    return this.authService.refreshTokens(body.id, body.refreshToken);
  }

  @Post('/logout')
  async logout(@GetUser('userId') userId: number) {
    return this.authService.logout(userId);
  }
}
