import { Body, Controller, Get, Param, ParseIntPipe, Patch, Post, Put, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UserResponseDto } from './dto/user-response.dto';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  async register(@Body() dto: CreateUserDto): Promise<UserResponseDto> {
    const user = await this.usersService.create(dto);
    return UserResponseDto.from(user);
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  async me(@Req() req): Promise<UserResponseDto> {
    const user = await this.usersService.findById(req.user.sub);
    return UserResponseDto.from(user);
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id/orders')
  async ordersOfUser(@Param('id', ParseIntPipe) id: number) {
    return this.usersService.findOrdersByUser(id);
  }

  @UseGuards(JwtAuthGuard)
  @Put(':id')
  async update(@Param('id', ParseIntPipe) id: number, @Body() body: any) {
    return this.usersService.update(id, body);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('me/password')
  async changePassword(@Req() req, @Body('password') password: string) {
    await this.usersService.changePassword(req.user.sub, password);
    return { updated: true };
  }
}
