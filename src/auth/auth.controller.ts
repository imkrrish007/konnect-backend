import { JwtService } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import {
  Body,
  Controller,
  Get,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { Request, Response } from 'express';
import { JWTAuthGuard } from './guards/jwt-auth.guard';
import { User } from './schemas/user.schema';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly jwtService: JwtService,
  ) {}

  @Post('register')
  async register(@Body() userDto: RegisterDto) {
    const user = await this.authService.register(userDto);
    if (!user) {
      return {
        isSuccess: false,
        message: 'User already exists',
      };
    }
    return {
      isSuccess: true,
      data: {
        ...user,
        name: user.firstName + ' ' + user.lastName,
      },
    };
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto, @Res() res: Response) {
    const { email, password } = loginDto;

    const user = await this.authService.findByEmail(email);

    if (user && (await bcrypt.compare(password, user.password))) {
      const token = this.jwtService.sign(
        {
          _id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          name: user.firstName + ' ' + user.lastName,
        },
        {
          secret: process.env.JWT_SECRET,
        },
      );

      res.cookie('__session', token, {
        domain: process.env.FE_BASE_URL,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
      });

      return res.json({
        isSuccess: true,
        message: 'Login successful',
      });
    } else {
      return res.status(HttpStatus.BAD_REQUEST).json({
        message: 'Invalid credentials',
      });
    }
  }

  @Post('logout')
  async logout(@Res() res: Response) {
    res.clearCookie('__session', {
      domain: process.env.FE_BASE_URL,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    return res.json({
      isSuccess: true,
      message: 'Logout successful',
    });
  }

  @UseGuards(JWTAuthGuard)
  @Get('info')
  async getInfo(@Req() req: Request) {
    const user = req.user as User;

    return {
      isSuccess: true,
      data: {
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        name: user.firstName + ' ' + user.lastName,
        email: user.email,
      },
    };
  }
}
