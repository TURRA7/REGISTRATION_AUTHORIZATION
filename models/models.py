from typing import Optional
from pydantic import BaseModel, field_validator
import re


class UserReg(BaseModel):
    email: str
    login: str
    password: str
    password_two: Optional[str] = None

    class Config:
        anystr_strip_whitespace = True

    @field_validator('email')
    def validate_email(cls, value: str):
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', value):
            raise ValueError('Неверный формат почты')
        return value

    @field_validator('login')
    def validate_login(cls, value: str):
        if not re.match(r'^[a-zA-Z0-9_-]+$', value):
            raise ValueError("Логин должен содержать только буквы, "
                             "цифры и символы: - или _")
        if not (5 <= len(value) <= 25):
            raise ValueError('Длина логина должна быть от 5 до 25 символов')
        return value

    @field_validator('password')
    def validate_password(cls, value: str):
        if len(value) < 7:
            raise ValueError(
                'Длина пароля должна быть не менее 7 символов')
        if not any(char.islower() for char in value):
            raise ValueError(
                'Пароль должен содержать хотя бы одну строчную букву')
        if not any(char.isupper() for char in value):
            raise ValueError(
                'Пароль должен содержать хотя бы одну заглавную букву')
        if not any(char.isdigit() for char in value):
            raise ValueError('Пароль должен содержать хотя бы одну цифру')
        if not ('-' in value or '_' in value):
            raise ValueError(
                'Пароль должен содержать один из символов "-" или "_"')
        return value


class CodeConfirm(BaseModel):
    code: str

    class Config:
        anystr_strip_whitespace = True


class UserAuth(BaseModel):
    login: str
    password: str
    remember_me: bool


class Recover(BaseModel):
    user: str

    class Config:
        anystr_strip_whitespace = True

    @field_validator('user')
    def validate_email(cls, value: str):
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', value):
            raise ValueError('Неверный формат почты')
        return value


class PasswordChange(BaseModel):
    password: str
    password_two: str

    class Config:
        anystr_strip_whitespace = True

    @field_validator('password')
    def validate_password(cls, value: str):
        if len(value) < 7:
            raise ValueError(
                'Длина пароля должна быть не менее 7 символов')
        if not any(char.islower() for char in value):
            raise ValueError(
                'Пароль должен содержать хотя бы одну строчную букву')
        if not any(char.isupper() for char in value):
            raise ValueError(
                'Пароль должен содержать хотя бы одну заглавную букву')
        if not any(char.isdigit() for char in value):
            raise ValueError('Пароль должен содержать хотя бы одну цифру')
        if not ('-' in value or '_' in value):
            raise ValueError(
                'Пароль должен содержать один из символов "-" или "_"')
        return value


class Token(BaseModel):
    token: str
