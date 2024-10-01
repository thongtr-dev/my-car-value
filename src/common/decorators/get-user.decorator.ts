import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { AuthenticatedRequest } from 'src/modules/auth/interfaces/authenticated-request.interface';

export const GetUser = createParamDecorator(
  (data: keyof AuthenticatedRequest['user'], ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest<AuthenticatedRequest>();
    const user = request.user;
    return data ? user?.[data] : user;
  }
);
