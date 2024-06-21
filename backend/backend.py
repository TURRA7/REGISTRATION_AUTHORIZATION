"""Моудль backand проекта."""

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
    WOKR_PORT, WORK_HOSTNAME)
from jwt_tools.jwt import create_jwt_token


async def is_valid_email(email) -> bool:
    """Функция для проверки того, являются ли введённые данные почтой"""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(email_regex, email):
        return True
    else:
        return False


async def send_email(email: str, message: str, context: str):
    """
    Функция отправляет пользователю сообщение на почту.

    args:
        context_ssl: представляет собой контекст для SSL
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

        args:
            user_log: Получение юзера по логину
            user_mail: Получение юзера по почте
            code: Сгенерированный 4х значный код
            email, login, password: Данные из формы полученые от API

        return:
            1. Получаем юзера по почте user_mail и логину user_log,
            2. Проверяем наличие юзера БД.
            3. Если пользователь присутствует:
            В состояния сессии, передаётся: email, login, password,
            code(одноразовый 4х значный код). В блоке try - выполняется
            получение шаблона, далее на указаную почту,
            отправляется код(code) и возвращается
            соответствующий JSONResponse ответ.
        """
        if not email:
            return {"message": "Введите вашу почту!",
                    "status_code": 400}
        elif not await is_valid_email(email):
            return {"message": "Введите правильную почту!",
                    "status_code": 400}
        elif not login:
            return {"message": "Введите ваш логин!",
                    "status_code": 400}
        elif len(login) < 5:
            return {"message": ("Логин должен состоять как минимум "
                                "из 5 символов: соджержать латинские "
                                "строчные и заглавные буквы, цифры и "
                                "символы '_' или '-'."),
                    "status_code": 400}
        elif not password or not password_two:
            return {"message": "Введите пароль и его повтор в поле ниже",
                    "status_code": 400}
        elif len(password) < 7:
            return {"message": ("Пароль должен состоять как минимум "
                                "из 7 символов: соджержать латинские "
                                "строчные и заглавные буквы, цифры и "
                                "символы '_' или '-'."),
                    "status_code": 400}
        elif password != password_two:
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
        Обработка формы ввода 'кода подтверждения регистрации'.
        password: Пароль из формы.
        verification_code: Код из сессии, созданый в функции registration
        code: данные из формы

        return:
            1. Получаются данные из сессии
            2. Проверка введённого кода с кодом сохранённым в сессии
            3. Добавление пользователя в базу данных функцией
            add_user(пароль с помощью generate_password_hash() передаётся
            в виде хэша)
            4. Очистка сессии
            5. Передача соответствующего JSONResponse ответа
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

        args:
            login, password = Данные из формы полученые от API
            user: Получение пользователя из базы данных по логину или почте
            code: Одноразовый 4х значный, сгенерированный код

        return:
            1. Присваивает переменной user результат получения данных из базы
            с логином или паролем
            2. Проводит аутентификацию по логину и паролю.
            3. Если 2 пункт выполнен, генерирует код, отправляет его на почту
            4. Метод возвращает dict в зависимости от
            результата выполнения функций
        """
        if not login:
            return {"message": "Введите ваш логин!",
                    "status_code": 400}
        elif not password:
            return {"message": "Введите ваш пароль!",
                    "status_code": 400}
        else:
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
        Метод подтверждения авторизации, по введенному коду.

        args:
            verification_code: Код полученный из сессии.
            code: Данные из формы

        return:
            Метод возвращает результат сравнения verification_code
            и code, в виде dict
        """
        if str(code) == str(verification_code):
            token = create_jwt_token(login, 12, SECRET_KEY)
            return {"message": "Авторизация удалась!",
                    "token": token, "status_code": 200}
        else:
            return {"message": "Введенный код неверный!", "status_code": 400}


class PasswordRecovery:
    """Работа с восстановлением пароля на маршрутах POST."""

    @staticmethod
    async def recover_pass(user: str) -> dict:
        """
        Обработка логики восстановление пароля.

        args:
            user: почта пользователя

        return:
            1. Проверяет, явлеются ли введённые данные почтой
            2. В переменную result передаются данные пользователя из БД
            3. Генерируется 4х значный код
            4. На указаную почту отправляется код с выбранным шаблоном
            5. Далее метод возвращает dict с кодом, почтой и статус-кодом
        """
        if not is_valid_email(user):
            return {"message": "Укажите почту, а не логин!",
                    "status_code": 400}
        else:
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
        Подтверждение восстановления, кодом с почты.

        args:
            code: Код из формы, полученный с API
            verification_code: Код полученный из сессии

        return:
            1. Проверяет коды на соответствие
            2. Метод возвращает dict с сообщением и статус-кодом
        """
        if str(code) == str(verification_code):
            return {"message": "Можете менять пароль!", "status_code": 200}
        else:
            return {"message": "Введенный код неверный!", "status_code": 400}

    @staticmethod
    async def new_password(email: str, password: str,
                           password_two: str) -> dict:
        """
        Функция восствновления пароля(изменение пароля).

        args:
            email, password: Данные, получены из формы с API

        return:
            1. Введённый пароль обновляется
            2. Метод возвращает dict с сообщением и статус-кодом
        """
        if not password or not password_two:
            {"message": "Введите новый пароль и повторите его в поле ниже!",
             "status_code": 400}
        elif len(password) < 7:
            return {"message": ("Пароль должен состоять как минимум "
                                "из 7 символов: соджержать латинские "
                                "строчные и заглавные буквы, цифры и "
                                "символы '_' или '-'."),
                    "status_code": 400}
        elif password != password_two:
            return {"message": "Пароли не сопадают!",
                    "status_code": 400}
        else:
            try:
                await update_password(email, generate_password_hash(password))
                return {"message": "Пароль обновлён!", "status_code": 200}
            except Exception as ex:
                return {"message": ex, "status_code": 400}
