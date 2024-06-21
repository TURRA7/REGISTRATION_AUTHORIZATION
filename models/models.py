from pydantic import BaseModel


class UserModel(BaseModel):
    name: str
    password: str

    class Config:
        orm_mode = True