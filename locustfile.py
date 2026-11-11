
from locust import HttpUser, task, between


class LoginUser(HttpUser):
    wait_time = between(0, 0)

    @task
    def login(self):
        self.client.post(
            "/api/login/",
            json={
                "username": "load_test_user",
                "password": "WrongPassword123!"
            }
        )
