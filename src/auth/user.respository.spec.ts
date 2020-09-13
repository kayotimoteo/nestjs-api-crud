import { ConflictException, InternalServerErrorException } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import * as bcryptjs from 'bcryptjs'

import { User } from './user.entity'
import { UserRepository } from './user.repository'
const mockCredentialsDto = {
  username: 'TestUsername',
  password: 'TestPassword'
}

describe('UserRepository', () => {
  let userRepository

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      providers: [UserRepository]
    }).compile()

    userRepository = await module.get<UserRepository>(UserRepository)
  })

  describe('signUp', () => {
    let save
    beforeEach(() => {
      save = jest.fn()
      userRepository.create = jest.fn().mockReturnValue({ save })
    })
    it('successfully signs up the user', () => {
      save.mockResolvedValue(undefined)
      expect(userRepository.signUp(mockCredentialsDto)).resolves.not.toThrow()
    })

    it('throws a conflict exception as username already exists', async () => {
      save.mockRejectedValue({ code: '23505' })

      await expect(userRepository.signUp(mockCredentialsDto)).rejects.toThrow(
        ConflictException
      )
    })
    it('throws a conflict exception as username already exists', async () => {
      save.mockRejectedValue({ code: '123456' })

      await expect(userRepository.signUp(mockCredentialsDto)).rejects.toThrow(
        InternalServerErrorException
      )
    })
  })

  describe('validateUserPassword', () => {
    let user

    beforeEach(() => {
      userRepository.findOne = jest.fn()
      user = new User()
      user.username = 'TestUserName'
      user.validatePassword = jest.fn()
    })

    it('returns the username as validation is successful', async () => {
      userRepository.findOne.mockResolvedValue(user)
      user.validatePassword.mockResolvedValue(true)

      const result = await userRepository.validateUserPassword(
        mockCredentialsDto
      )
      expect(result).toEqual('TestUserName')
    })
    it('returns null as user cannot be found', async () => {
      userRepository.findOne.mockResolvedValue(null)
      const result = await userRepository.validateUserPassword(
        mockCredentialsDto
      )
      expect(user.validatePassword).not.toHaveBeenCalled()
      expect(result).toBeNull()
    })
    it('returns null as password is invalid', async () => {
      userRepository.findOne.mockResolvedValue(user)
      user.validatePassword.mockResolvedValue(false)
      const result = await userRepository.validateUserPassword(
        mockCredentialsDto
      )
      expect(user.validatePassword).toHaveBeenCalled()
      expect(result).toBeNull()
    })
  })

  describe('hashPassword', () => {
    it('calls bcryptjs.hash to generate a hash', async () => {
      bcryptjs.hash = jest.fn().mockResolvedValue('testHash')
      expect(bcryptjs.hash).not.toHaveBeenCalled()
      const result = await userRepository.hashPassword(
        'testPassword',
        'testSalt'
      )
      expect(bcryptjs.hash).toHaveBeenCalled()
      expect(result).toEqual('testHash')
    })
  })
})
