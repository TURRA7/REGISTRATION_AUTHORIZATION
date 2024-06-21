"""
Модуль по работе с JWT токеном.

func:
    create_jwt_token: Создание jwt токена, на основе
    переданой информации о пользователе (почте или логину)

    decode_jwt_token: Декодирование jwt токена,
    получение информации о пользователе

    token_required: Декоратор, для защиты маршрутов
    с помощью проверки токена
"""
import jwt
from datetime import datetime, timezone, timedelta
from functools import wraps
from fastapi import HTTPException, Request


def create_jwt_token(login: str, token_lifetime_hours: int,
                     secret_key: str) -> str:
    """
    Создание JWT токена.

    args:
        login: Логин или почта пользователя
        token_lifetime_hours: Время жизни токена в часах
        secret_key: Секретный ключ для подписи

    return:
        Возвращает строку - токен
    """
    time_token = token_lifetime_hours
    # Словарь для приведения в токен (логин+время жизни токена)
    payload = {
        "login": login,
        "exp": datetime.now(timezone.utc) + timedelta(hours=time_token)
    }
    return jwt.encode(payload, secret_key,
                      algorithm="HS256")  # <- Метод шитфрования


def decode_jwt_token(token: str, secret_key: str) -> dict:
    """
    Декодирование JWT токена.

    args:
        token: jwt токен для декодирования
        secret_key: Секретный ключ для подписи

    return:
        Возвращает в зависимости от ответа или декодированную информацию
        о пользователе или ошибку
    """
    try:
        return jwt.decode(token, secret_key, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return {"message": "Токен истек", "status_code": 401}
    except jwt.InvalidTokenError:
        return {"message": "Недействительный токен", "status_code": 401}


def token_required(f):
    @wraps(f)
    async def decorated_function(request: Request, *args, **kwargs):
        # Получение токена из заголовков запроса
        token = request.headers.get("Authorization")
        # Проверка наличия токена
        if not token:
            raise HTTPException(status_code=403,
                                detail="Токен не предоставлен")
        try:
            # Обработка токена и декодирование
            token = token.split(" ")[1]  # Ожидается формат "Bearer <token>"
            data = decode_jwt_token(token)
        except Exception as e:
            raise HTTPException(status_code=401, detail=str(e))
        # Сохранение данных пользователя в состоянии запроса
        request.state.user = data
        # Вызов оригинальной декорированной функции
        return await f(request, *args, **kwargs)
    # Возврат декорированной функции
    return decorated_function
