import * as bcript from 'bcrypt'
import { Task } from 'src/tasks/task.entity'
import {
  BaseEntity,
  Column,
  Entity,
  OneToMany,
  PrimaryGeneratedColumn,
  Unique
} from 'typeorm'

@Entity()
@Unique(['username'])
export class User extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: number

  @Column()
  username: string

  @Column()
  password: string

  @Column()
  salt: string

  @OneToMany(type => Task, task => task.user, { eager: true })
  tasks: Task[]

  async validatePassword(password: string): Promise<boolean> {
    const hash = await bcript.hash(password, this.salt)
    return hash === this.password
  }
}