
from locust import HttpUser, task, between
import random


# class LoginUser(HttpUser):
#     wait_time = between(0, 0)

#     ip_addresses = [
#         "192.168.1.10",
#         "192.168.1.20",
#         "192.168.1.30",
#     ]

#     @task
#     def login(self):
#         simulated_ip = random.choice(self.ip_addresses)

#         self.client.post(
#             "/api/login/",
#             headers={
#                 # "X-Test-Client-IP": simulated_ip,
#                 "X-Test-Client-IP": "192.168.1.99",
#             },
#             json={
#                 "username": "ip_throttle_test_user",
#                 "password": "WrongPassword123!"
#             }
#         )




# class LoginUser(HttpUser):
#     wait_time = between(0, 0)

#     ip_addresses = [
#         "192.168.1.10",
#         "192.168.1.20",
#         "192.168.1.30",
#     ]

#     @task
#     def login(self):
#         simulated_ip = random.choice(self.ip_addresses)

#         self.client.post(
#             "/api/login/",
#             headers={
#                 "X-Test-Client-IP": simulated_ip,
#             },
#             json={
#                 "username": "distributed_test_user",
#                 "password": "WrongPassword123!"
#             }
#         )





class LoginUser(HttpUser):
    host = "http://127.0.0.1"
    wait_time = between(0, 0)

    @task
    def login(self):
        port = random.choice([8000, 8001])

        simulated_ip = f"192.168.100.{random.randint(1, 200)}"

        self.client.post(
            f"{self.host}:{port}/api/login/",
            headers={"X-Test-Client-IP": simulated_ip},
            json={
                "username": "concurrent_test_user",
                "password": "WrongPassword123!"
            }
        )
