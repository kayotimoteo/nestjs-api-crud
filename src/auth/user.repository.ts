import { ConflictException, InternalServerErrorException } from '@nestjs/common'

import * as bcryptjs from 'bcryptjs'
import { EntityRepository, Repository } from 'typeorm'

import { AuthCredentialsDto } from './dto/auth-credencials.dto'
import { User } from './user.entity'

@EntityRepository(User)
export class UserRepository extends Repository<User> {
  async signUp(authCredentialsDto: AuthCredentialsDto): Promise<void> {
    const { username, password } = authCredentialsDto

    const user = this.create()
    user.username = username
    user.salt = await bcryptjs.genSalt()
    user.password = await this.hashPassword(password, user.salt)

    try {
      await user.save()
    } catch (err) {
      if (err.code === '23505') {
        throw new ConflictException('Username already exists')
      } else {
        throw new InternalServerErrorException()
      }
    }
  }

  async validateUserPassword(
    authCredentialsDto: AuthCredentialsDto
  ): Promise<string> {
    const { username, password } = authCredentialsDto

    const user = await this.findOne({ username })

    if (user && (await user.validatePassword(password))) {
      return user.username
    } else {
      return null
    }
  }

  private async hashPassword(password: string, salt: string) {
    return bcryptjs.hash(password, salt)
  }
}
