import pytest


@pytest.mark.parametrize(
    "item, expected_status, expected_response",
    [
        ({"email": "kaplya7@mail.ru", "login": "Kolya777", "password": "Ponchik_78900", "password_two": "Ponchik_78900"}, 200, {"key": "kaplya7@mail.ru"}),
    ]
)
@pytest.mark.asyncio
async def test_registration(async_test_client, item,
                            expected_status, expected_response):
    response = await async_test_client.post("/registration/", json=item)
    assert response.status_code == expected_status
    assert response.json() == expected_response


"""
        ({"email": "...", "login": "...", "password": "...", "password_two": "..."}, ..., {"message": "..."}),
        ({"email": "...", "login": "...", "password": "...", "password_two": "..."}, ..., {"message": "..."}),
        ({"email": "...", "login": "...", "password": "...", "password_two": "..."}, ..., {"message": "..."}),
        ({"email": "...", "login": "...", "password": "...", "password_two": "..."}, ..., {"message": "..."})
"""