from fastapi import APIRouter, Form, Header, Request
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
async def registration(request: Request,
                       email: str = Form(...),
                       login: str = Form(...),
                       password: str = Form(...),
                       password_two: str = Form(...)
                       ) -> JSONResponse:
    """
    Обработка регистрации.

    args:
        result: Обработка пользователя: добавление в БД,
        отправка кода на почту

    return:
        Возвращает готовый JSONResponse ответ с
        состоянием добавления пользователя
    """
    try:
        user_data = UserReg(
            email=email,
            login=login,
            password=password,
            password_two=password_two
        )
    except ValidationError as e:
        errors = [{'message': err['msg'].split('Value error, ')[-1]}
                  for err in e.errors()]
        return JSONResponse(content={"message": errors, "status_code": 422},
                            status_code=422)

    result = await Registration.register(user_data.email,
                                         user_data.login,
                                         user_data.password,
                                         user_data.password_two)
    if result['status_code'] == 200:
        request.session['email'] = user_data.email
        request.session['login'] = user_data.login
        request.session['password'] = user_data.password
        request.session['code'] = result['code']
        response = JSONResponse(content={"key": result["email"]},
                                status_code=200)
    else:
        response = JSONResponse(content={"message": result["message"]},
                                status_code=result["status_code"])
    return response


@app_reg.post("/confirm")
async def confirm(request: Request,
                  code: str = Form(...)) -> JSONResponse:
    """
    Обработка формы ввода 'кода подтверждения регистрации'.

    args:
        email, login, password, verification_code: Данные из сессии
        добавленные в на шаге регистрации
        result: Обработка ввода и подтверждение кода

    return:
        Возвращает готовый JSONResponse ответ с
        состоянием добавления пользователя
    """
    try:
        user_data = CodeConfirm(
            code=code
        )
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
        email, login, password, user_data.code, verification_code)
    if result['status_code'] == 200:
        request.session.clear()
        response = JSONResponse(content={"message": result["message"]},
                                status_code=200)
    else:
        response = JSONResponse(content={"message": result["message"]},
                                status_code=400)
    return response


@app_auth.post("/")
async def authorization(request: Request,
                        login: str = Form(...),
                        password: str = Form(...),
                        remember_me: bool = Form(False)
                        ) -> JSONResponse:
    """
    Обработчик логики авторизации.

    args:
        user: Пользователь из базы данных
        code: Сгенерированный 4х значный код
        response: JSONResponse ответ
        login, password: данные из формы
        remember_me: положение флажка 'запомнить меня' в форме

    return:
        Возвращает готовый JSONResponse ответ удачным или неудачным
        статусом авторизации, а так же сохраняет код отправленный на почту
        в сессию и задаёт куки для флага "запомнить меня"
    """
    user_data = UserAuth(
        login=login,
        password=password,
        remember_me=remember_me
    )
    result = await Authorization.authorization(user_data.login,
                                               user_data.password)
    if result['status_code'] == 200:
        request.session['code'] = result['code']
        request.session['login'] = user_data.login
        response = JSONResponse(content={"key": result["login"]},
                                status_code=200)
    else:
        response = JSONResponse(content={"message": result["message"]},
                                status_code=result['status_code'])
    if user_data.remember_me:
        result.set_cookie(key="remember_me", value="true", max_age=30*24*60*60)
    return response


@app_auth.post("/verification")
async def verification(request: Request,
                       code: str = Form(...)) -> JSONResponse:
    """
    Обработка формы ввода 'кода подтверждения авторизации'.

    args:
        code: Данные из формы
        result: Обработка ввода и подтверждение кода

    return:
        Возвращает готовый JSONResponse ответ с
        состоянием авторизации
    """
    try:
        user_data = CodeConfirm(
            code=code
        )
    except ValidationError as e:
        errors = [{'message': err['msg'].split('Value error, ')[-1]}
                  for err in e.errors()]
        return JSONResponse(content={"message": errors,
                                     "status_code": 422},
                            status_code=422)
    verification_code = request.session.get('code')
    login = request.session.get('login')
    result = await Authorization.confirm_auth(user_data.code,
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
async def recover(request: Request,
                  user: str = Form(...)) -> JSONResponse:
    """
    Обработчик логики восстановления(изменения) пароля.

    args:
        user: Данные из формы (введённая почта)
        response: JSONResponse ответ

    return:
        По результатам обновления пароля, возвращает
        соответствующий JSONResponse ответ, так же сессии
        задаётся индификатор SESSION_STATE_MAIL
    """
    try:
        user_data = Recover(
            user=user
        )
    except ValidationError as e:
        errors = [{'message': err['msg'].split('Value error, ')[-1]}
                  for err in e.errors()]
        return JSONResponse(content={"message": errors,
                                     "status_code": 422},
                            status_code=422)

    result = await PasswordRecovery.recover_pass(user_data.user)
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
                     code: str = Form(...)) -> JSONResponse:
    """
    Подтверждение восстановления, кодом с почты.

    Сессия очищается после 6х минут, если код вводится не верный.

    args:
        code: Данные из формы
        verification_code: Код полученный из сессии
        response: JSONResponse ответ

    return:
        1. Проверяет состояние сессии
        2. Получает код(verification_code) из сессии и
        сверяем его с кодом(code) введённым пользователем в сессии
        3. Коды сверяются в функции confirm_recover(), если
        проверка пройдена, старый индификатор сессии удаляется,
        на его место ставится новый SESSION_STATE_CODE
        4. Функция возвращает соответствующий JSONResponse ответ
    """
    try:
        user_data = CodeConfirm(
            code=code
        )
    except ValidationError as e:
        errors = [{'message': err['msg'].split('Value error, ')[-1]}
                  for err in e.errors()]
        return JSONResponse(content={"message": errors,
                                     "status_code": 422},
                            status_code=422)
    if request.session.get('state') == SESSION_STATE_MAIL:
        verification_code = request.session.get('code')
        result = await PasswordRecovery.confirm_recover(
            user_data.code, verification_code)
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
                          password: str = Form(...),
                          password_two: str = Form(...)
                          ) -> JSONResponse:
    """
    Функция восствновления пароля(изменение пароля).

    Сессия очищается после 6х минут, если код вводится не верный.

    args:
        verification_code: Код полученный из сессии.
        password: Данные из формы(пароль)
        password_two: Данные из формы(повтор пароля)
        email: Почта пользователя из сессии
        result: Резуклтат изменения(dict) пароля в базе данных
        response: JSONResponse ответ

    return:
        1. Проверяем состояние сессии
        2. Получаем из сессии почту и изменяем пароль в update_password
        3. Метод возвращает JSONResponse ответ
    """
    try:
        user_data = PasswordChange(
            password=password,
            password_two=password_two
        )
    except ValidationError as e:
        errors = [{'message': err['msg'].split('Value error, ')[-1]}
                  for err in e.errors()]
        return JSONResponse(content={"message": errors,
                                     "status_code": 422},
                            status_code=422)

    if request.session.get('state') == SESSION_STATE_CODE:
        email = request.session.get('email')
        result = await PasswordRecovery.new_password(email, user_data.password,
                                                     user_data.password_two)
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
async def logout(request: Request, token: str = Header(...)) -> JSONResponse:
    """Обработчик выхода пользователя"""
    user_data = Token(
        token=token
    )
    result = await Logout.delete_token(user_data.token)
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
