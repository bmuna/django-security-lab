
from unittest.mock import patch

from django.test import SimpleTestCase

from users.throttles import (
    GlobalLoginRateThrottle,
    RedisUnavailable,
)

from redis.exceptions import ConnectionError as RedisConnectionError


class GlobalLoginRateThrottleTests(SimpleTestCase):

    @patch("users.throttles.get_redis_connection")
    def test_redis_connection_failure_returns_503(self, mock_redis):
        mock_redis.side_effect = RedisConnectionError("Redis is unavailable")

        throttle = GlobalLoginRateThrottle()

        with self.assertRaises(RedisUnavailable):
            throttle.allow_request(request=None, view=None)
    
    
    
    @patch("users.throttles.get_redis_connection")
    def test_wait_redis_failure_returns_503(self, mock_redis):
        mock_redis.side_effect = RedisConnectionError(
            "Redis is unavailable"
        )

        throttle = GlobalLoginRateThrottle()

        with self.assertRaises(RedisUnavailable):
            throttle.wait()
