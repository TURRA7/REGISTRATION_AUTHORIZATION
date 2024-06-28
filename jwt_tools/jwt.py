import jwt
from datetime import datetime, timezone, timedelta
from functools import wraps
from fastapi import HTTPException, Request


def create_jwt_token(login: str, token_lifetime_hours: int,
                     secret_key: str) -> str:
    """
    Создание JWT токена.

    Args:
        login (str): Логин или почта пользователя.
        token_lifetime_hours (int): Время жизни токена в часах.
        secret_key (str): Секретный ключ для подписи.

    Returns:
        str: Сгенерированный JWT токен.
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

    Args:
        token (str): JWT токен для декодирования.
        secret_key (str): Секретный ключ для подписи.

    Returns:
        dict: Декодированные данные токена или сообщение об ошибке.
    """
    try:
        return jwt.decode(token, secret_key, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return {"message": "Токен истек", "status_code": 401}
    except jwt.InvalidTokenError:
        return {"message": "Недействительный токен", "status_code": 401}


def token_required(f):
    """
    Декоратор для защиты маршрутов с помощью проверки наличия JWT токена.

    Args:
        f (function): Декорируемая функция, которая требует
        проверки наличия JWT токена.

    Returns:
        function: Декорированная функция, которая проверяет
        наличие и валидность JWT токена.
    """
    @wraps(f)
    async def decorated_function(request: Request, *args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            raise HTTPException(status_code=403,
                                detail="Токен не предоставлен")
        try:
            token = token.split(" ")[1]
            data = decode_jwt_token(token)
        except Exception as e:
            raise HTTPException(status_code=401, detail=str(e))
        request.state.user = data
        return await f(request, *args, **kwargs)
    return decorated_function
