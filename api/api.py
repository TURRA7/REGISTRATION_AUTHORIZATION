from typing import Annotated

from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse

from backend.backend import Authorization, PasswordRecovery, Registration
from config import SESSION_STATE_CODE, SESSION_STATE_MAIL


# Роутеры, для формы регистрации
app_reg = APIRouter(prefix="/registration")
# Роутеры, для формы авторизации
app_auth = APIRouter(prefix="/authorization")
# Роутеры для логаута
app_logout = APIRouter(prefix="/logout")


@app_reg.post("/")
async def registration(request: Request,
                       email: Annotated[str, Form()],
                       login: Annotated[str, Form()],
                       password: Annotated[str, Form()],
                       password_two: Annotated[str, Form()]
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
    result = await Registration.register(email, login, password, password_two)
    if result['status_code'] == 200:
        request.session['email'] = email
        request.session['login'] = login
        request.session['password'] = password
        request.session['code'] = result['code']
        response = JSONResponse(content={"key": result["email"]},
                                status_code=200)
    else:
        response = JSONResponse(content={"message": result["message"]},
                                status_code=result["status_code"])
    return response


@app_reg.post("/confirm")
async def confirm(request: Request,
                  code: Annotated[str, Form()]) -> JSONResponse:
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
    email = request.session.get('email')
    login = request.session.get('login')
    password = request.session.get('password')
    verification_code = request.session.get('code')
    result = await Registration.confirm_register(
        email, login, password, code, verification_code)
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
                        login: Annotated[str, Form()],
                        password: Annotated[str, Form()],
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
    result = await Authorization.authorization(login, password)
    if result['status_code'] == 200:
        request.session['code'] = result['code']
        request.session['login'] = login
        response = JSONResponse(content={"key": result["login"]},
                                status_code=200)
    else:
        response = JSONResponse(content={"message": result["message"]},
                                status_code=result['status_code'])
    if remember_me:
        result.set_cookie(key="remember_me", value="true", max_age=30*24*60*60)
    return response


@app_auth.post("/verification")
async def verification(request: Request,
                       code: Annotated[str, Form()]) -> JSONResponse:
    """
    Обработка формы ввода 'кода подтверждения авторизации'.

    args:
        code: Данные из формы
        result: Обработка ввода и подтверждение кода

    return:
        Возвращает готовый JSONResponse ответ с
        состоянием авторизации
    """
    verification_code = request.session.get('code')
    login = request.session.get('login')
    result = await Authorization.confirm_auth(code, verification_code, login)
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
                  user: Annotated[str, Form()]) -> JSONResponse:
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
    result = await PasswordRecovery.recover_pass(user)
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
                     code: Annotated[str, Form()]) -> JSONResponse:
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
    if request.session.get('state') == SESSION_STATE_MAIL:
        verification_code = request.session.get('code')
        result = await PasswordRecovery.confirm_recover(
            code, verification_code)
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
                          password: Annotated[str, Form()],
                          password_two: Annotated[str, Form()]
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
    if request.session.get('state') == SESSION_STATE_CODE:
        email = request.session.get('email')
        result = await PasswordRecovery.new_password(email, password,
                                                     password_two)
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
async def logout(request: Request) -> JSONResponse:
    """Обработчик выхода пользователя"""
    pass
