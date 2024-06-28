"""Моудль backand проекта."""

from datetime import timedelta
import ssl
import re
import smtplib
import random
from string import Template
from werkzeug.security import generate_password_hash, check_password_hash

from database.FDataBase import (
    add_user, select_by_email, select_by_user, update_password)
from config import (
    SECRET_KEY, WOKR_EMAIL, WOKR_EMAIL_PASS,
    WOKR_PORT, WORK_HOSTNAME, ACCESS_TOKEN_EXPIRE_MINUTES)
from jwt_tools.jwt import create_jwt_token
from redis_tools.redis_tools import redis_client


async def is_valid_email(email) -> bool:
    """
    Проверяет, является ли строка допустимым email адресом.

    Args:
        email (str): Строка для проверки.

    Returns:
        bool: True, если строка соответствует формату email, иначе False.
    """
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(email_regex, email):
        return True
    else:
        return False


async def send_email(email: str, message: str, context: str):
    """
    Функция отправляет пользователю сообщение на почту.

    Args:
        email (str): Адрес электронной почты получателя.
        message (str): Текст сообщения для отправки.
        context (str): Контекст для подстановки в шаблон сообщения.

    Raises:
        smtplib.SMTPRecipientsRefused: Если сервер почты отклонил получателей.
        smtplib.SMTPServerDisconnected: Если сервер почты отключил соединение.
        smtplib.SMTPException: Для общих ошибок SMTP.
        Exception: Возможны другие неуказанные ошибки.

    Notes:
        Функция использует SMTP_SSL для отправки сообщения.
        Использует предоставленный контекст для SSL.
        Шаблонизирует сообщение с использованием контекста перед отправкой.
    """
    context_ssl = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL(WORK_HOSTNAME, WOKR_PORT,
                              context=context_ssl, timeout=2) as server:
            server.login(WOKR_EMAIL, WOKR_EMAIL_PASS)
            message = Template(message).substitute(context)
            server.sendmail(WOKR_EMAIL, email, message.encode('utf-8'))
    except smtplib.SMTPRecipientsRefused as ex:
        print(f"SMTPRecipientsRefused error: {ex}")
        raise
    except smtplib.SMTPServerDisconnected as ex:
        print(f"SMTPServerDisconnected error: {ex}")
        raise
    except smtplib.SMTPException as ex:
        print(f"SMTP error: {ex}")
        raise
    except Exception as ex:
        print(f"General error: {ex}")
        raise


class Registration:
    """Работа с регистрацией на маршрутах POST."""

    @staticmethod
    async def register(email: str, login: str,
                       password: str, password_two: str) -> dict:
        """
        Обработка логики регистрации.

        Args:
            email (str): Адрес электронной почты пользователя.
            login (str): Логин пользователя.
            password (str): Пароль пользователя.
            password_two (str): Повторно введенный пароль для подтверждения.

        Returns:
            dict: Результат регистрации.
            - "email" (str): Email пользователя.
            - "login" (str): Логин пользователя.
            - "password" (str): Пароль пользователя.
            - "code" (int): Одноразовый четырехзначный код.
            - "status_code" (int): Код статуса операции.

        Notes:
            - Проверяет соответствие введенных паролей.
            - Проверяет наличие пользователя по логину и почте в базе данных.
            - Генерирует четырехзначный код.
            - Отправляет код подтверждения на указанный email.
        """
        if password != password_two:
            return {"message": "Введённые пароли не совпадают!",
                    "status_code": 400}
        else:
            user_log = await select_by_user(login)
            user_mail = await select_by_email(email)
            if user_log or user_mail:
                return {"message": ("Пользователь с таким логином"
                                    "или почтой, уже существует!"),
                        "status_code": 400}
            code = random.randint(1000, 9999)
            with open('template_message/t_code.txt',
                      'r', encoding='utf-8') as file:
                content = file.read()
            await send_email(email, content, {'code': code})
            return {"email": email, "login": login,
                    "password": password, "code": code, "status_code": 200}

    @staticmethod
    async def confirm_register(email: str, login: str,
                               password: str, code: str,
                               verification_code: str) -> dict:
        """
        Обработка формы ввода кода подтверждения регистрации.

        Args:
            email (str): Адрес электронной почты пользователя.
            login (str): Логин пользователя.
            password (str): Пароль пользователя.
            code (str): Код, введенный пользователем для
            подтверждения регистрации.
            verification_code (str): Код подтверждения из сессии,
            созданный при регистрации.

        Returns:
            dict: Результат подтверждения регистрации.
            - "message" (str): Сообщение о результате операции.
            - "status_code" (int): Код статуса операции.

        Notes:
            - Проверяет соответствие введенного кода с кодом из сессии.
            - Добавляет пользователя в базу данных с захешированным паролем.
            - Очищает сессию после успешного подтверждения.
        """
        if str(code) == str(verification_code):
            await add_user(email, login, generate_password_hash(password))
            return {"message": "Введенный код верный!", "status_code": 200}
        else:
            return {"message": "Введенный код неверный!", "status_code": 400}


class Authorization:
    """Работа с авторизацией на маршрутах POST."""

    @staticmethod
    async def authorization(login: str, password: str) -> dict:
        """
        Обработка логики авторизации.

        Args:
            login (str): Логин или адрес электронной почты пользователя.
            password (str): Пароль пользователя.

        Returns:
            dict: Результат авторизации.
            - "login" (str): Логин пользователя.
            - "code" (int): Одноразовый четырехзначный код для подтверждения.
            - "status_code" (int): Код статуса операции.

        Notes:
            - Проверяет тип введенных данных (логин или email).
            - Проверяет наличие пользователя в базе данных.
            - Проводит аутентификацию по логину и паролю.
            - Генерирует и отправляет код подтверждения на указанный email.
        """
        if await is_valid_email(login):
            user = await select_by_email(login)
        else:
            user = await select_by_user(login)
        if not user or not check_password_hash(user[0].password, password):
            return {"message": "Неверный логин или пароль!",
                    "status_code": 400}
        else:
            code = random.randint(1000, 9999)
            try:
                with open('template_message/t_pass.txt',
                          'r', encoding='utf-8') as file:
                    content = file.read()
                await send_email(user[0].email, content, {'code': code})
                return {"login": login, "code": code, "status_code": 200}
            except Exception as ex:
                return {"message": str(ex), "status_code": 400}

    @staticmethod
    async def confirm_auth(code: str,
                           verification_code: str, login: str) -> dict:
        """
        Подтверждение авторизации по введенному коду.

        Args:
            code (str): Код, введенный пользователем для подтверждения.
            verification_code (str): Код подтверждения из сессии.
            login (str): Логин пользователя.

        Returns:
            dict: Результат подтверждения авторизации.
            - "message" (str): Сообщение о результате операции.
            - "token" (str): JWT токен для доступа к ресурсам.
            - "status_code" (int): Код статуса операции.

        Notes:
            - Проверяет соответствие введенного кода с кодом из сессии.
            - Создает JWT токен для пользователя.
            - Сохраняет токен в Redis с истечением срока действия.
        """
        if str(code) == str(verification_code):
            token = create_jwt_token(login, 12, SECRET_KEY)
            await redis_client.setex(
                f"token:{token}",
                timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES)),
                login)
            return {"message": "Авторизация удалась!",
                    "token": token, "status_code": 200}
        else:
            return {"message": "Введенный код неверный!", "status_code": 400}


class PasswordRecovery:
    """Работа с восстановлением пароля на маршрутах POST."""

    @staticmethod
    async def recover_pass(user: str) -> dict:
        """
        Обработка логики восстановления пароля.

        Args:
            user (str): Адрес электронной почты пользователя.

        Returns:
            dict: Результат восстановления пароля.
            - "code" (int): Одноразовый четырехзначный код для подтверждения.
            - "user" (str): Адрес электронной почты пользователя.
            - "status_code" (int): Код статуса операции.

        Notes:
            - Проверяет существование пользователя в базе данных.
            - Генерирует и отправляет код подтверждения на указанный email.
        """
        result = await select_by_email(user)
        if not result:
            return {"message": "Пользователь не существует!",
                    "status_code": 400}
        else:
            try:
                code = random.randint(1000, 9999)
                with open('template_message/t_recover.txt',
                          'r', encoding='utf-8') as file:
                    content = file.read()
                await send_email(user, content, {'code': code})
                return {"code": code, "user": user, "status_code": 200}
            except Exception as ex:
                return {"message": str(ex), "status_code": 400}

    @staticmethod
    async def confirm_recover(code: str, verification_code: str) -> dict:
        """
        Подтверждение восстановления пароля по коду, полученному с почты.

        Args:
            code (str): Код, введенный пользователем для подтверждения.
            verification_code (str): Код подтверждения из сессии.

        Returns:
            dict: Результат подтверждения восстановления пароля.
            - "message" (str): Сообщение о результате операции.
            - "status_code" (int): Код статуса операции.

        Notes:
            - Проверяет соответствие введенного кода с кодом из сессии.
        """
        if str(code) == str(verification_code):
            return {"message": "Можете менять пароль!", "status_code": 200}
        else:
            return {"message": "Введенный код неверный!", "status_code": 400}

    @staticmethod
    async def new_password(email: str, password: str,
                           password_two: str) -> dict:
        """
        Изменение пароля пользователя.

        Args:
            email (str): Адрес электронной почты пользователя.
            password (str): Новый пароль пользователя.
            password_two (str): Повтор нового пароля пользователя.

        Returns:
            dict: Результат изменения пароля.
            - "message" (str): Сообщение о результате операции.
            - "status_code" (int): Код статуса операции.

        Notes:
            - Проверяет совпадение нового пароля и его повтора.
            - Обновляет пароль пользователя в базе данных.
        """
        if password != password_two:
            return {"message": "Пароли не сопадают!",
                    "status_code": 400}
        else:
            try:
                await update_password(email, generate_password_hash(password))
                return {"message": "Пароль обновлён!", "status_code": 200}
            except Exception as ex:
                return {"message": ex, "status_code": 400}


class Logout:
    """
        Удаление токена пользователя из базы данных redis.

        Args:
            token (str): Токен пользователя для удаления.

        Returns:
            dict: Результат операции удаления токена.
            - "message" (str): Сообщение о результате операции.
            - "status_code" (int): Код статуса операции.

        Notes:
            - Проверяет существование токена в базе данных redis.
            - Удаляет токен, если он существует.
    """
    @staticmethod
    async def delete_token(token: str):
        """Метод удаляет токен из базы данных redis."""
        if await redis_client.exists(token):
            await redis_client.delete(f"token:{token}")
            return {"message": "Выход выполнен!", "status_code": 308}
        else:
            return {"message": "Токен не валиден!", "status_code": 400}
