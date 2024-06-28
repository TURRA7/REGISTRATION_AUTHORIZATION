import pytest


class TestRegistration:
    @pytest.mark.parametrize(
        "item, expected_status, expected_response",
        [
            ({"email": "test@mail.ru", "login": "Kolya777",
              "password": "Vbn_78900", "password_two": "Vbn_78900"},
                200, "test@mail.ru"),
            ({"email": "test@mail", "login": "Kolya777",
              "password": "Vbn_78900", "password_two": "Vbn_78900"},
                422, "Неверный формат почты"),
            ({"email": "test@mail.ru", "login": "Koly_7",
              "password": "Vbn_78900", "password_two": "Vbn_78900"},
                422, "Длина логина должна быть не менее 7 символов"),
            ({"email": "test@mail.ru", "login": "KOLY_777",
              "password": "Vbn_78900", "password_two": "Vbn_78900"},
                422, "Логин должен содержать хотя бы одну строчную букву"),
            ({"email": "test@mail.ru", "login": "kolya_777",
              "password": "Vbn_78900", "password_two": "Vbn_78900"},
                422, "Логин должен содержать хотя бы одну заглавную букву"),
            ({"email": "test@mail.ru", "login": "Kolya_test",
              "password": "Vbn_78900", "password_two": "Vbn_78900"},
                422, "Логин должен содержать хотя бы одну цифру"),
            ({"email": "test@mail.ru", "login": "Kolya777",
              "password": "Te_7", "password_two": "Te_7"},
                422, "Длина пароля должна быть не менее 7 символов"),
            ({"email": "test@mail.ru", "login": "Kolya777",
              "password": "T_98088", "password_two": "T_98088"},
                422, "Пароль должен содержать хотя бы одну строчную букву"),
            ({"email": "test@mail.ru", "login": "Kolya777",
              "password": "t_98088", "password_two": "t_98088"},
                422, "Пароль должен содержать хотя бы одну заглавную букву"),
            ({"email": "test@mail.ru", "login": "Kolya777",
              "password": "Test_test", "password_two": "Test_test"},
                422, "Пароль должен содержать хотя бы одну цифру"),
            ({"email": "test@mail.ru", "login": "Kolya777",
              "password": "Test_777", "password_two": "Test_999"},
                400, "Введённые пароли не совпадают!"),
        ]
    )
    @pytest.mark.asyncio
    async def test_registration(self, async_test_client, item,
                                expected_status, expected_response):
        response = await async_test_client.post("/registration/", json=item)
        assert response.status_code == expected_status
        assert expected_response in response.text
