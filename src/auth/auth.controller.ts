import { UserService } from '../user/user.service';
import {
    Controller,
    Post,
    Body,
    BadRequestException,
    NotFoundException,
    Res
} from '@nestjs/common';
import { RegisterDto } from './dtos/register.dto';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import { ApiTags } from '@nestjs/swagger';

@ApiTags('Auth')
@Controller()
export class AuthController {
    constructor(
        private userService: UserService,
        private jwtService: JwtService
    ) {}

    @Post('admin/register')
    async register(@Body() body: RegisterDto) {
        const { password_confirm, ...data } = body;

        if (body.password !== password_confirm) {
            throw new BadRequestException('Passwords do not match!');
        }

        const hashed = await bcrypt.hash(body.password, 12);

        return this.userService.save({
            ...data,
            password: hashed,
            is_ambassador: false
        });
    }

    @Post('admin/login')
    async login(
        @Body('email') email: string,
        @Body('password') password: string,
        @Res({ passthrough: true }) response: Response
    ) {
        const user = await this.userService.findOne({ email });

        if (!user) {
            throw new NotFoundException('User not found!');
        }

        if (!(await bcrypt.compare(password, user.password))) {
            throw new BadRequestException('Invalid credentials!');
        }

        const jwt = await this.jwtService.signAsync({
            id: user.id
        });

        response.cookie('jwt', jwt, { httpOnly: true });

        return {
            message: 'Success'
        };
    }
}
