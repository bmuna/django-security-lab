import hashlib
from urllib import request
import uuid
import json
from datetime import datetime, timezone

from django_redis import get_redis_connection
from flask import request
from rest_framework.throttling import AnonRateThrottle, BaseThrottle
from rest_framework.exceptions import APIException
from redis.exceptions import (
    ConnectionError as RedisConnectionError,
    TimeoutError as RedisTimeoutError,
)
from django_redis.exceptions import ConnectionInterrupted


class RedisUnavailable(APIException):
    status_code = 503
    default_detail = "Authentication service temporarily unavailable."
    default_code = "redis_unavailable"
    

class LoginRateThrottle(AnonRateThrottle):
    scope = 'login'
    
    def get_ident(self, request):
        test_ip = request.headers.get('X-Test-Client-IP')

        if test_ip:
            return test_ip

        return super().get_ident(request)
    

    def allow_request(self, request, view):
        try:
            allowed = super().allow_request(request, view)

        except (
            RedisConnectionError,
            RedisTimeoutError,
            ConnectionInterrupted,
        ):
            raise RedisUnavailable()
        
        # allowed = super().allow_request(request, view)
        print("IP THROTTLE:", allowed, self.history, self.num_requests)

        self.request_count = len(self.history)

        record_rate_limit_event(
            limiter="ip",
            request_count=self.request_count,
            limit=self.num_requests,
            window=self.duration,
            decision="allowed" if allowed else "rejected",
            client_ip=self.get_ident(request),
        )

        return allowed

ACCOUNT_RISK_THRESHOLDS = {
    "medium": 5,
    "high": 8,
    "critical": 10,
}

MFA_RATE_LIMITS = {
    "challenge": {
        "limit": 5,
        "window": 300,
    },
    "account": {
        "limit": 10,
        "window": 900,
    },
    "ip": {
        "limit": 30,
        "window": 900,
    },
}

TOKEN_BUCKET_CAPACITY = 5
TOKEN_BUCKET_REFILL_RATE = 1
TOKEN_BUCKET_REFILL_INTERVAL = 10


LEAKY_BUCKET_CAPACITY = 5
LEAKY_BUCKET_INTERVAL = 2


def record_rate_limit_event(
    limiter,
    request_count,
    limit,
    window,
    decision,
    client_ip=None,
):
    try:
        redis_client = get_redis_connection('default')

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "limiter": limiter,
            "request_count": int(request_count),
            "limit": limit,
            "window_seconds": window,
            "decision": decision,
            "client_ip": client_ip,
        }

        key = "security:diagnostics:login"

        pipeline = redis_client.pipeline()

        pipeline.lpush(key, json.dumps(event))
        pipeline.ltrim(key, 0, 9999)
        pipeline.expire(key, 86400)

        pipeline.execute()

    except (ConnectionError, TimeoutError):
        pass
    




class GlobalLoginRateThrottle(BaseThrottle):
    GLOBAL_LOGIN_RATE_LIMIT_SCRIPT = """
    local current_count = redis.call('INCR', KEYS[1])

    if current_count == 1 or redis.call('TTL', KEYS[1]) == -1 then
        redis.call('EXPIRE', KEYS[1], ARGV[1])
    end

    return current_count
    """
 
    
    limit = 10
    window = 60
    key = 'security:login:global'

    def allow_request(self, request, view):
        redis_client = get_redis_connection('default')

        current_count = redis_client.eval(
            self.GLOBAL_LOGIN_RATE_LIMIT_SCRIPT,
            1,
            self.key,
            self.window
        )

        allowed = current_count <= self.limit

        record_rate_limit_event(
            limiter="global",
            request_count=current_count,
            limit=self.limit,
            window=self.window,
            decision="allowed" if allowed else "rejected",
            client_ip=self.get_ident(request),
        )

        return allowed
    
    def wait(self):
        redis_client = get_redis_connection('default')
        remaining_time = redis_client.ttl(self.key)

        return remaining_time if remaining_time > 0 else self.window
    

   
ACCOUNT_LOGIN_FAILURE_SCRIPT = """
local current_count = redis.call('INCR', KEYS[1])

if current_count == 1 or redis.call('TTL', KEYS[1]) == -1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end

return current_count
"""
    
def record_failed_login(username):
    redis_client = get_redis_connection('default')

    username_hash = hashlib.sha256(
        username.encode('utf-8')
    ).hexdigest()

    key = f'security:login:account:{username_hash}'

    return redis_client.eval(
        ACCOUNT_LOGIN_FAILURE_SCRIPT,
        1,
        key,
        300
    )
    
def reset_failed_login(username):
    redis_client = get_redis_connection('default')

    username_hash = hashlib.sha256(
        username.encode('utf-8')
    ).hexdigest()

    key = f'security:login:account:{username_hash}'

    redis_client.delete(key)
    
    
def get_account_risk_level(username):
    redis_client = get_redis_connection('default')

    username_hash = hashlib.sha256(
        username.encode('utf-8')
    ).hexdigest()

    key = f'security:login:account:{username_hash}'

    failed_attempts = int(redis_client.get(key) or 0)

    if failed_attempts >= ACCOUNT_RISK_THRESHOLDS["critical"]:
        return "critical"

    if failed_attempts >= ACCOUNT_RISK_THRESHOLDS["high"]:
        return "high"

    if failed_attempts >= ACCOUNT_RISK_THRESHOLDS["medium"]:
        return "medium"

    return "normal"


def is_mfa_rate_limited(user_id, challenge_id, ip_address):
    redis_client = get_redis_connection('default')

    ip_hash = hashlib.sha256(
        ip_address.encode('utf-8')
    ).hexdigest()

    keys = [
        f'security:mfa:challenge-attempts:{challenge_id}',
        f'security:mfa:account-attempts:{user_id}',
        f'security:mfa:ip-attempts:{ip_hash}',
    ]

    counts = redis_client.mget(keys)

    limits = [
        MFA_RATE_LIMITS["challenge"]["limit"],
        MFA_RATE_LIMITS["account"]["limit"],
        MFA_RATE_LIMITS["ip"]["limit"],
    ]

    for count, limit in zip(counts, limits):
        if int(count or 0) >= limit:
            return True

    return False


RECORD_MFA_FAILURE_SCRIPT = """
local results = {}

for i = 1, 3 do
    local current_count = redis.call('INCR', KEYS[i])

    if current_count == 1 or redis.call('TTL', KEYS[i]) == -1 then
        redis.call('EXPIRE', KEYS[i], ARGV[i])
    end

    results[i] = current_count
end

return results
"""


def record_mfa_failure(user_id, challenge_id, ip_address):
    redis_client = get_redis_connection('default')

    ip_hash = hashlib.sha256(
        ip_address.encode('utf-8')
    ).hexdigest()

    keys = [
        f'security:mfa:challenge-attempts:{challenge_id}',
        f'security:mfa:account-attempts:{user_id}',
        f'security:mfa:ip-attempts:{ip_hash}',
    ]

    return redis_client.eval(
        RECORD_MFA_FAILURE_SCRIPT,
        3,
        *keys,
        MFA_RATE_LIMITS["challenge"]["window"],
        MFA_RATE_LIMITS["account"]["window"],
        MFA_RATE_LIMITS["ip"]["window"],
    )
    
    
SLIDING_WINDOW_SCRIPT = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local member = ARGV[3]

-- Get the current time from Redis
local time = redis.call('TIME')
local now = (tonumber(time[1]) * 1000)
    + math.floor(tonumber(time[2]) / 1000)

-- Calculate the beginning of the rolling window
local window_start = now - (window * 1000)

-- Remove requests older than the last 60 seconds
redis.call(
    'ZREMRANGEBYSCORE',
    key,
    '-inf',
    window_start
)

-- Count requests still inside the window
local current_count = redis.call('ZCARD', key)

-- Reject if the limit has already been reached
if current_count >= limit then
    return 0
end

-- Record this request
redis.call('ZADD', key, now, member)

-- Automatically expire the Redis key
redis.call('EXPIRE', key, window)

return 1
"""


def allow_sliding_window_request(key, limit, window):
    redis_client = get_redis_connection('default')

    member = uuid.uuid4().hex

    result = redis_client.eval(
        SLIDING_WINDOW_SCRIPT,
        1,
        key,
        limit,
        window,
        member
    )

    return result == 1



TOKEN_BUCKET_SCRIPT = """
local key = KEYS[1]

local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local refill_interval = tonumber(ARGV[3])

-- Get the current time from Redis
local time = redis.call('TIME')
local now = tonumber(time[1])

-- Read the existing bucket
local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')

local tokens = tonumber(bucket[1])
local last_refill = tonumber(bucket[2])

-- Initialize a new bucket
if tokens == nil then
    tokens = capacity
    last_refill = now
end

-- Calculate elapsed time
local elapsed = math.max(0, now - last_refill)

-- Calculate how many complete refill intervals passed
local intervals = math.floor(elapsed / refill_interval)

-- Refill the bucket
if intervals > 0 then
    tokens = math.min(
        capacity,
        tokens + (intervals * refill_rate)
    )

    last_refill = last_refill + (intervals * refill_interval)
end

-- Reject if there are no tokens
if tokens < 1 then
    redis.call(
        'HSET',
        key,
        'tokens', tokens,
        'last_refill', last_refill
    )
    redis.call('EXPIRE', key, 3600)

    return 0
end

-- Consume one token
tokens = tokens - 1

-- Save the updated bucket
redis.call(
    'HSET',
    key,
    'tokens', tokens,
    'last_refill', last_refill
)

redis.call('EXPIRE', key, 3600)

return 1
"""

def allow_token_bucket_request(key):
    redis_client = get_redis_connection('default')

    result = redis_client.eval(
        TOKEN_BUCKET_SCRIPT,
        1,
        key,
        TOKEN_BUCKET_CAPACITY,
        TOKEN_BUCKET_REFILL_RATE,
        TOKEN_BUCKET_REFILL_INTERVAL,
    )

    return result == 1


class LoginTokenBucketThrottle(BaseThrottle):
    def allow_request(self, request, view):
        ip_address = request.META.get('REMOTE_ADDR', '')

        key = f'security:login:token-bucket:{ip_address}'

        return allow_token_bucket_request(key)

    def wait(self):
        return 10
    
    
    
    
LEAKY_BUCKET_SCRIPT = """
local key = KEYS[1]

local capacity = tonumber(ARGV[1])
local interval = tonumber(ARGV[2]) * 1000
local request_id = ARGV[3]

-- Get current Redis time in milliseconds
local time = redis.call('TIME')
local now = (tonumber(time[1]) * 1000)
    + math.floor(tonumber(time[2]) / 1000)

-- Check how many requests are waiting
local queue_size = redis.call('ZCARD', key)

-- Reject if the queue is full
if queue_size >= capacity then
    return {0, 0, queue_size}
end

-- Find the last scheduled request
local last = redis.call(
    'ZREVRANGE',
    key,
    0,
    0,
    'WITHSCORES'
)

local scheduled_at = now

if #last > 0 then
    local last_scheduled = tonumber(last[2])

    scheduled_at = math.max(now, last_scheduled) + interval
end

-- Add the request to the queue
redis.call(
    'ZADD',
    key,
    scheduled_at,
    request_id
)

return {1, scheduled_at, queue_size + 1}
"""



GET_NEXT_LEAKY_REQUEST_SCRIPT = """
local key = KEYS[1]

-- Get current Redis time in milliseconds
local time = redis.call('TIME')
local now = (tonumber(time[1]) * 1000)
    + math.floor(tonumber(time[2]) / 1000)

-- Find the earliest request whose scheduled time has arrived
local request = redis.call(
    'ZRANGEBYSCORE',
    key,
    '-inf',
    now,
    'LIMIT',
    0,
    1
)

if #request == 0 then
    return nil
end

-- Remove the request from the queue
redis.call('ZREM', key, request[1])

return request[1]
"""



def add_leaky_bucket_request(key):
    redis_client = get_redis_connection('default')

    request_id = uuid.uuid4().hex

    result = redis_client.eval(
        LEAKY_BUCKET_SCRIPT,
        1,
        key,
        LEAKY_BUCKET_CAPACITY,
        LEAKY_BUCKET_INTERVAL,
        request_id
    )

    accepted, scheduled_at, queue_size = result

    return {
        "accepted": bool(accepted),
        "scheduled_at": scheduled_at,
        "queue_size": queue_size,
    }
    
def get_next_leaky_request(key):
    redis_client = get_redis_connection('default')

    result = redis_client.eval(
        GET_NEXT_LEAKY_REQUEST_SCRIPT,
        1,
        key
    )

    if result is None:
        return None

    return result.decode('utf-8')