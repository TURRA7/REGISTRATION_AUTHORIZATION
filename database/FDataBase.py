"""Database module based on SQLAlchemy."""

from typing import List

from config import PG_USER, PG_PASS, PG_HOST, PG_PORT, PG_DB

from sqlalchemy import String, select, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.ext.asyncio import (
    create_async_engine, AsyncSession)
from sqlalchemy.orm import sessionmaker


engine = create_async_engine(
    f"postgresql+asyncpg://{PG_USER}:{PG_PASS}@{PG_HOST}:{PG_PORT}/{PG_DB}",
    echo=True)

async_session = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


class Base(DeclarativeBase):
    pass


class User(Base):
    """Таблица пользователя для регистрации и аутентификации."""
    __tablename__ = "user"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(30), nullable=False)
    password: Mapped[str] = mapped_column(Text, nullable=False)
    email: Mapped[str] = mapped_column(Text, nullable=False)
    role_id: Mapped[int] = mapped_column(default=1)

    def __repr__(self) -> str:
        return f"User(id={self.id!r}, name={self.name!r}, password={self.password!r})"


async def create_tables() -> None:
    """Функция создания таблиц."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def delete_tables() -> None:
    """Функция удаления таблиц."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def select_by_user(login) -> List[User]:
    """Получение данных из таблцы по логину."""
    async with AsyncSession(engine) as session:
        result = await session.execute(select(User).where(User.name == login))
        users = result.scalars().all()
        return users


async def select_by_email(email) -> List[User]:
    """Получение данных из таблцы по почте."""
    async with AsyncSession(engine) as session:
        result = await session.execute(select(User).where(User.email == email))
        users = result.scalars().all()
        return users


async def add_user(email, login, password) -> None:
    """Добавление пользователя в таблицу."""
    async with AsyncSession(engine) as session:
        async with session.begin():
            result = User(email=email, name=login, password=password)
            session.add(result)
            await session.commit()


async def update_password(email, password) -> None:
    """Изменение пароля пользователя по указанной почте."""
    async with AsyncSession(engine) as session:
        async with session.begin():
            user = await session.execute(
                select(User).where(User.email == email))
            result = user.scalars().first()
            if result:
                result.password = password
                await session.commit()
            else:
                # Заменить на логги в будущем
                print(f"User with login {email} not found.")
