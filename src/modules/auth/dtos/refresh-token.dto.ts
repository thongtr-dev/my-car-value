import { IsNumber, IsString } from 'class-validator';

export class RefreshTokenDTO {
  @IsNumber()
  id: number;

  @IsString()
  refreshToken: string;
}
