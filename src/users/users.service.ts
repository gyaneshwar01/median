import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import * as bcrypt from 'bcrypt';

export const roundsOfHashing = 10;

@Injectable()
export class UsersService {
  constructor(private prismaService: PrismaService) {}

  async create(createUserDto: CreateUserDto) {
    const hashedPassword = await bcrypt.hash(
      createUserDto.password,
      roundsOfHashing,
    );
    return this.prismaService.user.create({
      data: {
        ...createUserDto,
        password: hashedPassword,
      },
    });
  }

  findAll() {
    return this.prismaService.user.findMany({});
  }

  findOne(id: number) {
    return this.prismaService.user.findUnique({ where: { id } });
  }

  async update(id: number, updateUserDto: UpdateUserDto) {
    if (updateUserDto.password) {
      updateUserDto.password = await bcrypt.hash(
        updateUserDto.password,
        roundsOfHashing,
      );
    }
    return this.prismaService.user.update({
      where: {
        id,
      },
      data: updateUserDto,
    });
  }

  remove(id: number) {
    return this.prismaService.user.delete({
      where: {
        id,
      },
    });
  }
}
