# Задаём базовый образ Linux + Python 3.11.5
FROM python:3.12.3-alpine3.18

# Задаём рабочую папку
WORKDIR /app

# Копируем файлы из рабочей OS, в рабочую папку docker image
COPY .. /app

# Установка зависимостей для проекта
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

# Команда запуска контейнера
ENTRYPOINT ["python3", "main.py"]