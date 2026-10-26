"""Ограничение частоты запросов (скользящее окно). В проде - Redis / nginx limit_req;
здесь in-memory реализация для демонстрации принципа."""
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

_ALL = []


class RateLimiter:
    def __init__(self, limit: int, window: int):
        self.limit, self.window, self.hits = limit, window, defaultdict(deque)
        _ALL.append(self)

    def __call__(self, request: Request) -> None:
        key = request.client.host if request.client else "?"
        q, now = self.hits[key], time.time()
        while q and q[0] <= now - self.window:
            q.popleft()
        if len(q) >= self.limit:
            raise HTTPException(429, "Too many requests", headers={"Retry-After": str(self.window)})
        q.append(now)


def reset_all() -> None:
    for r in _ALL:
        r.hits.clear()
