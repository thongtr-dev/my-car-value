import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { IS_PUBLIC_KEY } from 'src/common/decorators/public.decorator';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly reflector: Reflector
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const access_token = this.extractAccessTokenFromHeader(request);

    if (!access_token) {
      throw new UnauthorizedException('Access token not found');
    }
    try {
      const payload = await this.jwtService.verifyAsync(access_token, {
        secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
      });
      request['user'] = {
        userId: payload.sub,
        email: payload.email,
      };
    } catch {
      throw new UnauthorizedException('Invalid access token');
    }

    return true;
  }

  private extractAccessTokenFromHeader(request: Request): string | undefined {
    const [type, access_token] =
      request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? access_token : undefined;
  }
}
