from logging.config import fileConfig
import asyncio
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine
from alembic import context

from database.FDataBase import Base


# Настройка логирования из файла конфигурации
config = context.config
fileConfig(config.config_file_name)


# Импортируем вашу базу данных и метаданные
target_metadata = Base.metadata


# Получаем URL базы данных из конфигурационного файла
url = config.get_main_option("sqlalchemy.url")
connectable = create_async_engine(url, poolclass=pool.NullPool, future=True)


def run_migrations_offline():
    """Запуск миграций в оффлайн-режиме.

    В этом режиме миграции применяются к базе данных без создания подключения.
    """
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online():
    """Запуск миграций в онлайн-режиме.

    В этом режиме создается подключение к базе данных и применяются миграции.
    """
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

if context.is_offline_mode():
    run_migrations_offline()
else:
    # Запуск асинхронной функции в синхронном контексте
    asyncio.run(run_migrations_online())
