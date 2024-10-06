import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

describe('AuthService', () => {
  let authService: AuthService;
  let usersService: Partial<UsersService>;
  let jwtService: Partial<JwtService>;
  let configService: Partial<ConfigService>;

  beforeEach(async () => {
    usersService = {
      find: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      findOne: jest.fn(),
    };
    jwtService = {
      signAsync: jest.fn(),
    };
    configService = {
      get: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: UsersService, useValue: usersService },
        { provide: JwtService, useValue: jwtService },
        { provide: ConfigService, useValue: configService },
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
  });

  describe('signup', () => {
    it('should throw an error if email is already in use', async () => {
      (usersService.find as jest.Mock).mockResolvedValue([
        { id: 1, email: 'test@test.com' },
      ]);
      await expect(
        authService.signup('test@test.com', 'password')
      ).rejects.toThrow(BadRequestException);
    });

    it('should create a new user successfully', async () => {
      (usersService.find as jest.Mock).mockResolvedValue([]);
      (usersService.create as jest.Mock).mockResolvedValue({
        id: 1,
        email: 'test@test.com',
      });
      const result = await authService.signup('test@test.com', 'password');
      expect(result).toEqual({ message: 'User created successfully' });
    });
  });

  describe('signin', () => {
    it('should throw an error if email is not found', async () => {
      (usersService.find as jest.Mock).mockResolvedValue([]);
      await expect(
        authService.signin('test@test.com', 'password')
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw an error if password does not match', async () => {
      (usersService.find as jest.Mock).mockResolvedValue([
        { id: 1, email: 'test@test.com', password: 'hashedPassword' },
      ]);
      jest
        .spyOn(bcrypt, 'compare')
        .mockImplementation(() => Promise.resolve(false));
      await expect(
        authService.signin('test@test.com', 'password')
      ).rejects.toThrow(BadRequestException);
    });

    it('should sign in successfully', async () => {
      (usersService.find as jest.Mock).mockResolvedValue([
        { id: 1, email: 'test@test.com', password: 'hashedPassword' },
      ]);
      jest
        .spyOn(bcrypt, 'compare')
        .mockImplementation(() => Promise.resolve(true));
      jest.spyOn(jwtService, 'signAsync').mockResolvedValue('token');
      const result = await authService.signin('test@test.com', 'password');
      expect(result).toEqual({
        id: 1,
        email: 'test@test.com',
        access_token: 'token',
        refresh_token: 'token',
      });
    });
  });

  describe('refreshTokens', () => {
    it('should throw an error if user is not found', async () => {
      (usersService.findOne as jest.Mock).mockResolvedValue(null);
      await expect(
        authService.refreshTokens(1, 'refreshToken')
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw an error if refresh token does not match', async () => {
      (usersService.findOne as jest.Mock).mockResolvedValue({
        id: 1,
        refreshToken: 'hashedToken',
      });
      jest
        .spyOn(bcrypt, 'compare')
        .mockImplementation(() => Promise.resolve(false));
      await expect(
        authService.refreshTokens(1, 'refreshToken')
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw an error if refresh token has expired', async () => {
      (usersService.findOne as jest.Mock).mockResolvedValue({
        id: 1,
        refreshToken: 'hashedToken',
        refreshTokenExpiration: Math.floor(Date.now() / 1000) - 1,
      });
      jest
        .spyOn(bcrypt, 'compare')
        .mockImplementation(() => Promise.resolve(true));
      await expect(
        authService.refreshTokens(1, 'refreshToken')
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should refresh tokens successfully', async () => {
      (usersService.findOne as jest.Mock).mockResolvedValue({
        id: 1,
        email: 'test@test.com',
        refreshToken: 'hashedToken',
        refreshTokenExpiration: Math.floor(Date.now() / 1000) + 1000,
      });
      jest
        .spyOn(bcrypt, 'compare')
        .mockImplementation(() => Promise.resolve(true));
      jest.spyOn(jwtService, 'signAsync').mockResolvedValue('newToken');
      const result = await authService.refreshTokens(1, 'refreshToken');
      expect(result).toEqual({
        id: 1,
        email: 'test@test.com',
        access_token: 'newToken',
        refresh_token: 'newToken',
      });
    });
  });

  describe('logout', () => {
    it('should throw an error if user is not found', async () => {
      (usersService.findOne as jest.Mock).mockResolvedValue(null);
      await expect(authService.logout(1)).rejects.toThrow(BadRequestException);
    });

    it('should logout successfully', async () => {
      (usersService.findOne as jest.Mock).mockResolvedValue({
        id: 1,
        email: 'test@test.com',
      });
      const result = await authService.logout(1);
      expect(result).toEqual({ message: 'Logged out successfully' });
    });
  });
});
