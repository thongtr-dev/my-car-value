import { Expose } from 'class-transformer';

export class AuthResponseDto {
  @Expose()
  id: number;

  @Expose()
  email: string;

  @Expose()
  access_token: string;

  @Expose()
  refresh_token: string;
}
