# Микросервис Регистрации и Авторизации Пользователей

Этот микросервис предоставляет функционал для регистрации и авторизации пользователей.

## Функциональные возможности

- **Регистрация пользователей**: Пользователи могут зарегистрироваться, предоставив необходимые данные.
- **Авторизация пользователей**: Пользователи могут войти в систему, используя зарегистрированные учетные данные.
- **JWT-аутентификация**: Для безопасной аутентификации используются JSON Web Tokens (JWT).
- **Шифрование паролей**: Пароли надежно шифруются с использованием PBKDF2.
- **Ролевая модель доступа**: Различные роли и разрешения для пользователей.

## Содержание

- [Микросервис Регистрации и Авторизации Пользователей](#микросервис-регистрации-и-авторизации-пользователей)
  - [Функциональные возможности](#функциональные-возможности)
  - [Содержание](#содержание)
  - [Начало работы](#начало-работы)
    - [Предварительные требования](#предварительные-требования)
    - [Установка](#установка)
    - [Запуск сервиса](#запуск-сервиса)
  - [API Документация](#api-документация)
  - [Тестирование](#тестирование)

## Начало работы

Эти инструкции помогут вам запустить копию проекта на локальном компьютере для целей разработки и тестирования.

### Предварительные требования

- Python (>=13.x)

### Установка

1. Клонируйте репозиторий
    ```sh
    git clone https://github.com/TURRA7/REGISTRATION_AUTHORIZATION.git
    ```
2. Перейдите в директорию проекта
    ```sh
    cd yourrepository
    ```
3. В
   ```
   
   ```
    

### Запуск сервиса


    ```

Сервер будет запущен на `http://localhost:8000`.

## API Документация

Подробное описание API доступно по адресу `http://localhost:8000/docs`

## Тестирование

Запуск тестов:
```sh
pytest
```
