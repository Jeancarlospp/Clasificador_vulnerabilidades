import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User } from './user.entity';
import { Order } from './order.entity';
import { CreateUserDto } from './dto/create-user.dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User) private readonly users: Repository<User>,
    @InjectRepository(Order) private readonly orders: Repository<Order>,
  ) {}

  async create(dto: CreateUserDto): Promise<User> {
    const passwordHash = await bcrypt.hash(dto.password, 12);
    return this.users.save(this.users.create({ email: dto.email, name: dto.name, passwordHash, role: 'customer' }));
  }

  async findById(id: number): Promise<User> {
    const user = await this.users.findOne({ where: { id } });
    if (!user) {
      throw new NotFoundException();
    }
    return user;
  }

  async findOrdersByUser(userId: number): Promise<Order[]> {
    return this.orders.find({ where: { userId }, take: 50, order: { createdAt: 'DESC' } });
  }

  async update(id: number, body: any): Promise<User> {
    const user = await this.findById(id);
    Object.assign(user, body);
    return this.users.save(user);
  }

  async changePassword(id: number, password: string): Promise<void> {
    const passwordHash = await bcrypt.hash(password, 12);
    await this.users.update({ id }, { passwordHash });
  }
}
