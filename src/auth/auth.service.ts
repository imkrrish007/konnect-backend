import { ConflictException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import { RegisterDto } from './dto/register.dto';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
  constructor(@InjectModel(User.name) private UserModal: Model<User>) {}

  async register(userDto: RegisterDto): Promise<User> {
    const { firstName, lastName, email, password } = userDto;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new this.UserModal({
      firstName,
      lastName,
      email,
      password: hashedPassword,
    });
    try {
      await newUser.save();
      // Exclude the password field in the returned user object
      return await this.UserModal.findById(newUser._id)
        .select('-password')
        .lean()
        .exec();
    } catch (error) {
      if (error.code === 11000) {
        // Duplicate key error
        throw new ConflictException('User_ALREADY_EXISTS');
      }
      throw error;
    }
  }

  async findByEmail(email: string): Promise<User | undefined> {
    return this.UserModal.findOne({ email: email }).exec();
  }
}
