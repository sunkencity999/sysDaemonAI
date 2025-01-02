"""Task manager for handling asynchronous tasks."""

from enum import Enum
import asyncio
from typing import Any, Callable, Dict, Optional, Union

class TaskPriority(Enum):
    """Priority levels for tasks."""
    LOW = 0
    MEDIUM = 1
    HIGH = 2

class TaskManager:
    """Manages asynchronous tasks with priority levels."""
    
    def __init__(self):
        """Initialize the task manager."""
        self.tasks: Dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()
    
    async def add_task(self, name: str, coro_func: Callable[..., Any], *args,
                      priority: TaskPriority = TaskPriority.MEDIUM,
                      **kwargs) -> asyncio.Task:
        """Add a new task to be executed.
        
        Args:
            name: Unique name for the task
            coro_func: Coroutine function to execute
            *args: Arguments to pass to the coroutine
            priority: Priority level for the task
            **kwargs: Keyword arguments to pass to the coroutine
            
        Returns:
            The created task
        """
        async with self._lock:
            if name in self.tasks:
                raise ValueError(f"Task {name} already exists")
            
            task = asyncio.create_task(
                coro_func(*args, **kwargs),
                name=name
            )
            self.tasks[name] = task
            return task
    
    async def cancel_task(self, name: str) -> None:
        """Cancel a running task.
        
        Args:
            name: Name of the task to cancel
        """
        async with self._lock:
            if name in self.tasks:
                task = self.tasks[name]
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                del self.tasks[name]
    
    async def get_task_status(self, name: str) -> Optional[str]:
        """Get the status of a task.
        
        Args:
            name: Name of the task
            
        Returns:
            Status of the task or None if not found
        """
        if name not in self.tasks:
            return None
        
        task = self.tasks[name]
        if task.done():
            return "completed"
        elif task.cancelled():
            return "cancelled"
        else:
            return "running"
    
    async def wait_for_task(self, name: str, timeout: Optional[float] = None) -> Any:
        """Wait for a task to complete.
        
        Args:
            name: Name of the task
            timeout: Maximum time to wait in seconds
            
        Returns:
            Result of the task
            
        Raises:
            asyncio.TimeoutError: If timeout is reached
            KeyError: If task not found
        """
        if name not in self.tasks:
            raise KeyError(f"Task {name} not found")
            
        task = self.tasks[name]
        try:
            result = await asyncio.wait_for(task, timeout)
            return result
        finally:
            if task.done():
                del self.tasks[name]
