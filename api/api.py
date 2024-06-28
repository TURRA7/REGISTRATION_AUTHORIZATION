from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from backend.backend import (Authorization, Logout,
                             PasswordRecovery, Registration)
from config import SESSION_STATE_CODE, SESSION_STATE_MAIL
from models.models import (CodeConfirm, PasswordChange,
                           Recover, Token, UserAuth, UserReg)


# Роутеры, для формы регистрации
app_reg = APIRouter(prefix="/registration")
# Роутеры, для формы авторизации
app_auth = APIRouter(prefix="/authorization")
# Роутеры для логаута
app_logout = APIRouter(prefix="/logout")


@app_reg.post("/")
async def registration(request: Request, data: UserReg) -> JSONResponse:
    """
    Регистрация пользователя.

    Args:
        request (Request): HTTP запрос.
        data (UserReg): Данные пользователя.

    Returns:
        JSONResponse: Результат регистрации.
        - 200: Успешная регистрация, возвращает ключ 'key' (email).
        - 422: Ошибка валидации, возвращает сообщение об ошибке.
        - Другие коды: Соответствующие сообщения об ошибках и коды статусов.
    Notes:
        - При успешном результате из бэкенда,
        сохраняет в сессию данные пользователя
    """
    try:
        data = UserReg(**data.model_dump())
    except ValidationError as e:
        errors = [{'message': err['msg'].split('Value error, ')[-1]}
                  for err in e.errors()]
        return JSONResponse(content={"message": errors, "status_code": 422},
                            status_code=422)

    result = await Registration.register(data.email,
                                         data.login,
                                         data.password,
                                         data.password_two)
    if result['status_code'] == 200:
        request.session['email'] = data.email
        request.session['login'] = data.login
        request.session['password'] = data.password
        request.session['code'] = result['code']
        response = JSONResponse(content={"key": result["email"]},
                                status_code=200)
    else:
        response = JSONResponse(content={"message": result["message"]},
                                status_code=result["status_code"])
    return response


@app_reg.post("/confirm")
async def confirm(request: Request, data: CodeConfirm) -> JSONResponse:
    """
    Обработка формы ввода кода подтверждения регистрации.

    Args:
        request (Request): HTTP запрос.
        data (CodeConfirm): Данные с кодом подтверждения.

    Returns:
        JSONResponse: Результат подтверждения кода.
        - 200: Успешное подтверждение, возвращает сообщение об успехе.
        - 422: Ошибка валидации, возвращает сообщение об ошибке.
        - 400: Ошибка подтверждения, возвращает соответствующее сообщение.
    Notes:
        - Получает данные из сессии, отправляет на бэкенд, при успешном
        ответе с бэкенда, очищает сессию.
    """
    try:
        data = CodeConfirm(**data.model_dump())
    except ValidationError as e:
        errors = [{'message': err['msg'].split('Value error, ')[-1]}
                  for err in e.errors()]
        return JSONResponse(content={"message": errors,
                                     "status_code": 422},
                            status_code=422)

    email = request.session.get('email')
    login = request.session.get('login')
    password = request.session.get('password')
    verification_code = request.session.get('code')
    result = await Registration.confirm_register(
        email, login, password, data.code, verification_code)
    if result['status_code'] == 200:
        request.session.clear()
        response = JSONResponse(content={"message": result["message"]},
                                status_code=200)
    else:
        response = JSONResponse(content={"message": result["message"]},
                                status_code=400)
    return response


@app_auth.post("/")
async def authorization(request: Request, data: UserAuth) -> JSONResponse:
    """
    Обработчик логики авторизации.

    Args:
        request (Request): HTTP запрос.
        data (UserAuth): Данные для авторизации.

    Returns:
        JSONResponse: Результат авторизации.
        - 200: Успешная авторизация, возвращает ключ 'key' (login).
        - Другие коды: Соответствующие сообщения об ошибках и коды статусов.

    Notes:
        - Сохраняет код, отправленный на почту, и логин в сессию.
        - Если установлен флажок 'запомнить меня',
        устанавливает соответствующую куку.
    """
    result = await Authorization.authorization(data.login,
                                               data.password)
    if result['status_code'] == 200:
        request.session['code'] = result['code']
        request.session['login'] = data.login
        response = JSONResponse(content={"key": result["login"]},
                                status_code=200)
    else:
        response = JSONResponse(content={"message": result["message"]},
                                status_code=result['status_code'])
    if data.remember_me:
        response.set_cookie(key="remember_me", value="true",
                            max_age=30*24*60*60)
    return response


@app_auth.post("/verification")
async def verification(request: Request, data: CodeConfirm) -> JSONResponse:
    """
    Обработка формы ввода кода подтверждения авторизации.

    Args:
        request (Request): HTTP запрос.
        data (CodeConfirm): Данные с кодом подтверждения.

    Returns:
        JSONResponse: Результат подтверждения кода.
        - 200: Успешное подтверждение, возвращает сообщение и токен,
        очищает сессию.
        - 422: Ошибка валидации, возвращает сообщение об ошибке.
        - Другие коды: Соответствующие сообщения об ошибках и коды статусов.
    Notes:
        - Получает код и логин из сессии, передаёт на бэкенд, при успешном
        ответе с бэкенда, очищает сессию.
    """
    try:
        data = CodeConfirm(**data.model_dump())
    except ValidationError as e:
        errors = [{'message': err['msg'].split('Value error, ')[-1]}
                  for err in e.errors()]
        return JSONResponse(content={"message": errors,
                                     "status_code": 422},
                            status_code=422)
    verification_code = request.session.get('code')
    login = request.session.get('login')
    result = await Authorization.confirm_auth(data.code,
                                              verification_code, login)
    if result['status_code'] == 200:
        request.session.clear()

        # Здесь может быть перенаправление на нужный вам микросервис
        # <--- код --->
        # Для декодирования токена в другом микросервисе,
        # а так же для защиты маршрутов, следует применять модуль jwt_tools

        response = JSONResponse(content={"message": result["message"],
                                         "token": result["token"]},
                                status_code=result['status_code'])
    else:
        response = JSONResponse(content={"message": result["message"]},
                                status_code=result['status_code'])
    return response


@app_auth.post("/recover")
async def recover(request: Request, data: Recover) -> JSONResponse:
    """
    Обработчик логики восстановления (изменения) пароля.

    Args:
        request (Request): HTTP запрос.
        data (Recover): Данные для восстановления пароля.

    Returns:
        JSONResponse: Результат восстановления пароля.
        - 200: Успешное восстановление, возвращает email пользователя.
        - 422: Ошибка валидации, возвращает сообщение об ошибке.
        - Другие коды: Соответствующие сообщения об ошибках и коды статусов.

    Notes:
        - Устанавливает сессионный идентификатор SESSION_STATE_MAIL.
        - Сохраняет код подтверждения и email пользователя в сессии.
    """
    try:
        data = Recover(**data.model_dump())
    except ValidationError as e:
        errors = [{'message': err['msg'].split('Value error, ')[-1]}
                  for err in e.errors()]
        return JSONResponse(content={"message": errors,
                                     "status_code": 422},
                            status_code=422)

    result = await PasswordRecovery.recover_pass(data.user)
    if result['status_code'] == 200:
        request.session['state'] = SESSION_STATE_MAIL
        request.session['code'] = result['code']
        request.session['email'] = result['user']
        response = JSONResponse(content={"user": result["user"]},
                                status_code=result['status_code'])
    else:
        response = JSONResponse(content={"message": result["message"]},
                                status_code=result['status_code'])
    return response


@app_auth.post("/recover/reset_code")
async def reset_code(request: Request,
                     data: CodeConfirm) -> JSONResponse:
    """
    Подтверждение восстановления пароля кодом с почты.

    Args:
        request (Request): HTTP запрос.
        data (CodeConfirm): Данные с кодом подтверждения.

    Returns:
        JSONResponse: Результат подтверждения кода.
        - 200: Успешное подтверждение, обновление сессии.
        - 422: Ошибка валидации, возвращает сообщение об ошибке.
        - 400: Ошибка состояния сессии, почта не указана.

    Notes:
        - Проверяет состояние сессии.
        - Сверяет код из сессии с введенным пользователем.
        - При успешном подтверждении обновляет идентификатор сессии.
        - Сессия очищается через 6 минут, если код неверный. Время изменяется
        в переменных окружения.
    """
    try:
        data = CodeConfirm(**data.model_dump())
    except ValidationError as e:
        errors = [{'message': err['msg'].split('Value error, ')[-1]}
                  for err in e.errors()]
        return JSONResponse(content={"message": errors,
                                     "status_code": 422},
                            status_code=422)
    if request.session.get('state') == SESSION_STATE_MAIL:
        verification_code = request.session.get('code')
        result = await PasswordRecovery.confirm_recover(
            data.code, verification_code)
        if result['status_code'] == 200:
            del request.session['state']
            request.session['state'] = SESSION_STATE_CODE
            response = JSONResponse(content={"message": result["message"]},
                                    status_code=result['status_code'])
        else:
            response = JSONResponse(content={"message": result["message"]},
                                    status_code=result['status_code'])
        return response
    else:
        return JSONResponse(content={"message": "Вы не указали почту!"},
                            status_code=400)


@app_auth.post("/recover/reset_code/change_password")
async def change_password(request: Request,
                          data: PasswordChange) -> JSONResponse:
    """
    Изменение пароля после восстановления.

    Args:
        request (Request): HTTP запрос.
        data (PasswordChange): Данные для изменения пароля.

    Returns:
        JSONResponse: Результат изменения пароля.
        - 200: Успешное изменение пароля, сессия очищается.
        - 422: Ошибка валидации, возвращает сообщение об ошибке.
        - 400: Ошибка состояния сессии, код не введен.

    Notes:
        - Проверяет состояние сессии.
        - Изменяет пароль для пользователя с указанной почтой.
        - При успешном изменении пароля очищает сессию.
        - Сессия очищается через 6 минут, если код неверный. Время изменяется
        в переменных окружения.
    """
    try:
        data = PasswordChange(**data.model_dump())
    except ValidationError as e:
        errors = [{'message': err['msg'].split('Value error, ')[-1]}
                  for err in e.errors()]
        return JSONResponse(content={"message": errors,
                                     "status_code": 422},
                            status_code=422)

    if request.session.get('state') == SESSION_STATE_CODE:
        email = request.session.get('email')
        result = await PasswordRecovery.new_password(email, data.password,
                                                     data.password_two)
        if result['status_code'] == 200:
            request.session.clear()
            response = JSONResponse(content={"message": result["message"]},
                                    status_code=result['status_code'])
        else:
            response = JSONResponse(content={"message": result["message"]},
                                    status_code=result['status_code'])
        return response
    else:
        return JSONResponse(content={"message": "Вы не ввели код!"},
                            status_code=400)


@app_logout.post("/")
async def logout(request: Request, data: Token) -> JSONResponse:
    """
    Обработчик выхода пользователя.

    Args:
        request (Request): HTTP запрос.
        data (Token): Токен пользователя для выхода.

    Returns:
        JSONResponse: Результат выхода пользователя.
        - 308: Успешный выход, возможно с перенаправлением.
        - Другие коды: Соответствующие сообщения об ошибках и коды статусов.
    """
    result = await Logout.delete_token(data.token)
    if result['status_code'] == 308:
        # Здесь вы можете указать перенаправление на нужную
        # страницу в другом микросервисе после выхода пользователя
        # <--- код --->
        response = JSONResponse(content={"message": result["message"]},
                                status_code=result['status_code'])
    else:
        response = JSONResponse(content={"message": result["message"]},
                                status_code=result['status_code'])
    return response
