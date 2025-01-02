#!/usr/bin/env python3
import asyncio
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union
import logging
import functools
import time
from datetime import datetime
import aiohttp
import aiomultiprocess
from contextlib import asynccontextmanager

class TaskPriority(Enum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3

@dataclass
class Task:
    id: str
    coroutine: Callable
    args: tuple
    kwargs: dict
    priority: TaskPriority
    created_at: datetime
    timeout: Optional[float] = None

class AsyncTaskManager:
    def __init__(self, max_workers: int = None):
        self.logger = logging.getLogger(__name__)
        self.max_workers = max_workers or multiprocessing.cpu_count()
        self.process_pool = ProcessPoolExecutor(max_workers=self.max_workers)
        self.task_queues: Dict[TaskPriority, asyncio.PriorityQueue] = {
            priority: asyncio.PriorityQueue() for priority in TaskPriority
        }
        self.running_tasks: Dict[str, asyncio.Task] = {}
        self._shutdown = False
        
    async def start(self):
        """Start the task manager and worker tasks."""
        self.worker_tasks = [
            asyncio.create_task(self._worker(priority))
            for priority in TaskPriority
        ]
    
    async def stop(self):
        """Gracefully stop the task manager."""
        self._shutdown = True
        # Wait for all queues to be empty
        await asyncio.gather(*(queue.join() for queue in self.task_queues.values()))
        # Cancel worker tasks
        for task in self.worker_tasks:
            task.cancel()
        # Wait for worker tasks to finish
        await asyncio.gather(*self.worker_tasks, return_exceptions=True)
        self.process_pool.shutdown()
    
    async def submit(self, coroutine: Callable, *args, 
                    priority: TaskPriority = TaskPriority.MEDIUM,
                    timeout: Optional[float] = None,
                    **kwargs) -> str:
        """Submit a task to be executed."""
        task = Task(
            id=f"task_{time.time_ns()}",
            coroutine=coroutine,
            args=args,
            kwargs=kwargs,
            priority=priority,
            created_at=datetime.now(),
            timeout=timeout
        )
        await self.task_queues[priority].put((priority.value, task))
        return task.id
    
    async def _worker(self, priority: TaskPriority):
        """Worker coroutine that processes tasks from the queue."""
        queue = self.task_queues[priority]
        while not self._shutdown:
            try:
                _, task = await queue.get()
                self.logger.debug(f"Processing task {task.id} with priority {priority.name}")
                
                try:
                    if asyncio.iscoroutinefunction(task.coroutine):
                        if task.timeout:
                            coro = asyncio.wait_for(
                                task.coroutine(*task.args, **task.kwargs),
                                timeout=task.timeout
                            )
                        else:
                            coro = task.coroutine(*task.args, **task.kwargs)
                        self.running_tasks[task.id] = asyncio.create_task(coro)
                        await self.running_tasks[task.id]
                    else:
                        # Run CPU-intensive tasks in the process pool
                        loop = asyncio.get_event_loop()
                        await loop.run_in_executor(
                            self.process_pool,
                            task.coroutine,
                            *task.args,
                            **task.kwargs
                        )
                except asyncio.TimeoutError:
                    self.logger.warning(f"Task {task.id} timed out after {task.timeout}s")
                except Exception as e:
                    self.logger.error(f"Error processing task {task.id}: {str(e)}")
                finally:
                    if task.id in self.running_tasks:
                        del self.running_tasks[task.id]
                    queue.task_done()
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Worker error: {str(e)}")
                continue

class ConnectionPool:
    def __init__(self, min_size: int = 10, max_size: int = 100,
                 cleanup_interval: int = 60):
        self.min_size = min_size
        self.max_size = max_size
        self.cleanup_interval = cleanup_interval
        self.pool: List[aiohttp.ClientSession] = []
        self.in_use: Dict[aiohttp.ClientSession, bool] = {}
        self._lock = asyncio.Lock()
        self._cleanup_task = None
        
    async def start(self):
        """Initialize the connection pool."""
        async with self._lock:
            for _ in range(self.min_size):
                session = aiohttp.ClientSession()
                self.pool.append(session)
                self.in_use[session] = False
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def stop(self):
        """Close all connections in the pool."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
        async with self._lock:
            for session in self.pool:
                await session.close()
            self.pool.clear()
            self.in_use.clear()
    
    @asynccontextmanager
    async def acquire(self) -> aiohttp.ClientSession:
        """Acquire a connection from the pool."""
        session = await self._get_connection()
        try:
            yield session
        finally:
            await self._release_connection(session)
    
    async def _get_connection(self) -> aiohttp.ClientSession:
        """Get an available connection or create a new one."""
        async with self._lock:
            # Try to find an available connection
            for session in self.pool:
                if not self.in_use[session]:
                    self.in_use[session] = True
                    return session
            
            # Create new connection if pool not at max size
            if len(self.pool) < self.max_size:
                session = aiohttp.ClientSession()
                self.pool.append(session)
                self.in_use[session] = True
                return session
            
            # Wait for a connection to become available
            while True:
                for session in self.pool:
                    if not self.in_use[session]:
                        self.in_use[session] = True
                        return session
                await asyncio.sleep(0.1)
    
    async def _release_connection(self, session: aiohttp.ClientSession):
        """Release a connection back to the pool."""
        async with self._lock:
            if session in self.in_use:
                self.in_use[session] = False
    
    async def _cleanup_loop(self):
        """Periodically cleanup idle connections above min_size."""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self._cleanup_idle_connections()
            except asyncio.CancelledError:
                break
    
    async def _cleanup_idle_connections(self):
        """Remove idle connections above min_size."""
        async with self._lock:
            if len(self.pool) > self.min_size:
                idle_connections = [
                    session for session, in_use in self.in_use.items()
                    if not in_use
                ]
                for session in idle_connections[:(len(self.pool) - self.min_size)]:
                    await session.close()
                    self.pool.remove(session)
                    del self.in_use[session]

def cpu_bound(func: Callable) -> Callable:
    """Decorator to mark a function as CPU-bound for automatic process pool execution."""
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        loop = asyncio.get_event_loop()
        with ProcessPoolExecutor() as pool:
            return await loop.run_in_executor(pool, func, *args, **kwargs)
    return wrapper

async def run_in_process(func: Callable, *args, **kwargs) -> Any:
    """Run a CPU-intensive function in a separate process."""
    async with aiomultiprocess.Pool() as pool:
        return await pool.apply(func, args=args, kwds=kwargs)
