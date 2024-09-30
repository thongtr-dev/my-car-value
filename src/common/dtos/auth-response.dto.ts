import { Expose } from 'class-transformer';

export class AuthResponseDto {
  @Expose()
  access_token: string;
}
