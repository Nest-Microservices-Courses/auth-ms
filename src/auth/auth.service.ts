import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { LoginUserDto, RegisterUserDto } from './dto';
import * as bcrypt from 'bcrypt';
import { PrismaClient } from '@prisma/client';
import { RpcException } from '@nestjs/microservices';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger: Logger = new Logger(AuthService.name);

  constructor(
    private readonly jwtService: JwtService,
  ) {
    super();
  }

  singJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }


  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDb Connected');
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { name, email, password} = registerUserDto;
    try {
      const user = await this.user.findUnique({
        where: {email}
      });

      if(user) {
        throw new RpcException({
          status: HttpStatus.CONFLICT,
          message: `User already exist`,
        })
      }
      const newUser = await this.user.create({
        data: {
          email,
          password: bcrypt.hashSync(password, 10),
          name
        }
      })

      const { password: __, ...rest} = newUser;

      return {
        user: rest,
        token: this.singJWT(rest)
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      })
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password} = loginUserDto;
    try {
      const user = await this.user.findUnique({
        where: {email}
      });

      if(!user) {
        throw new RpcException({
          status: HttpStatus.UNAUTHORIZED,
          message: `User does not found`,
        })
      }
      

      const isPasswordValid = bcrypt.compareSync(password, user.password);

      if(!isPasswordValid) {
        throw new RpcException({
          status: HttpStatus.UNAUTHORIZED,
          message: `Password not valid`,
        })
      }

      const {password: __, ...rest } = user;

      return {
        user: rest,
        token: this.singJWT(rest)
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      })
    }
  }

  verifyToken(token: string) {
    try {
      const {sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return {
        user,
        token: this.singJWT(user),
      }
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.UNAUTHORIZED,
        message: 'Invalid Token'
      })
    }
  }
}
