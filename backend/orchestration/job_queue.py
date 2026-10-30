"""Async job queue for the sandbox tier (tiered latency).

exact-hash -> instant | static+KG -> synchronous | sandbox -> ASYNC (here).

MVP: in-process asyncio queue + background worker, so a single-node dev setup
works with no broker. Production: swap for Celery/RQ/Arq + Redis without changing
the enqueue/status API. TODO: implement CeleryJobQueue.
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Awaitable, Callable, Optional


class JobStatus(str, Enum):
    queued = "queued"
    running = "running"
    done = "done"
    failed = "failed"


@dataclass
class Job:
    job_id: str
    status: JobStatus = JobStatus.queued
    result: Optional[dict] = None
    error: Optional[str] = None
    meta: dict = field(default_factory=dict)

    @property
    def report_id(self) -> Optional[str]:
        return self.meta.get("report_id")


class AsyncJobQueue:
    def __init__(self) -> None:
        self._queue: asyncio.Queue = asyncio.Queue()
        self._jobs: dict[str, Job] = {}
        self._worker: Optional[asyncio.Task] = None

    def start(self) -> None:
        if self._worker is None:
            self._worker = asyncio.create_task(self._run())

    async def enqueue(self, coro_factory: Callable[[], Awaitable[dict]],
                      meta: Optional[dict] = None) -> str:
        job = Job(job_id=uuid.uuid4().hex, meta=meta or {})
        self._jobs[job.job_id] = job
        await self._queue.put((job.job_id, coro_factory))
        return job.job_id

    def status(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    async def _run(self) -> None:
        while True:
            job_id, factory = await self._queue.get()
            job = self._jobs[job_id]
            job.status = JobStatus.running
            try:
                job.result = await factory()
                job.status = JobStatus.done
            except Exception as exc:  # noqa: BLE001 - record + continue
                job.status = JobStatus.failed
                job.error = str(exc)
            finally:
                self._queue.task_done()


_queue: Optional[AsyncJobQueue] = None


def job_queue() -> AsyncJobQueue:
    global _queue
    if _queue is None:
        _queue = AsyncJobQueue()
    return _queue
