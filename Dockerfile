# Используем существующий базовый образ
FROM python:3.12-slim

# Устанавливаем необходимые пакеты
RUN apt-get update && apt-get install -y \
    nginx \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем зависимости Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем ваше приложение
COPY . /app
WORKDIR /app

# Копируем конфигурацию Nginx
COPY nginx.conf /etc/nginx/nginx.conf

# Экспонируем порты
EXPOSE 8000 80

# Запуск Nginx и вашего приложения
# Указываем базовый образ Python
FROM python:3.12-slim

# Создаем рабочую директорию
WORKDIR /app

# Копируем файлы зависимостей
COPY requirements.txt .

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Копируем оставшиеся файлы приложения
COPY . .

# Открываем порт 8000 для доступа к приложению
EXPOSE 8000

# Команда запуска приложения в формате JSON
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
