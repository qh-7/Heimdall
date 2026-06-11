"""可复用的后台任务执行器。

每个任务在独立守护线程内开一个 event loop 跑协程, 通过 threading.Event 协作式取消。
抽自原 app/main.py 的 _running_threads/_cancel_flags/_bg_run, 供两个领域共用。
"""
from __future__ import annotations

import asyncio
import sys
import threading
from typing import Awaitable, Callable


class BackgroundTaskRunner:
    """管理一组后台任务线程与各自的取消标志。"""

    def __init__(self) -> None:
        self._threads: dict[int, threading.Thread] = {}
        self._cancel_flags: dict[int, threading.Event] = {}
        self._lock = threading.Lock()

    def start(self, task_id: int,
              coro_factory: Callable[[threading.Event], Awaitable[None]]) -> threading.Event:
        """启动后台任务。coro_factory(cancel_evt) 返回要 await 的协程。"""
        cancel_evt = threading.Event()
        with self._lock:
            self._cancel_flags[task_id] = cancel_evt

        def _run() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(coro_factory(cancel_evt))
            except Exception as e:  # 任务自身一般已捕获异常; 这里兜底防止线程静默崩溃
                print(f"[taskrunner] task {task_id} crashed: {e}", file=sys.stderr, flush=True)
            finally:
                loop.close()
                with self._lock:
                    self._cancel_flags.pop(task_id, None)
                    self._threads.pop(task_id, None)

        t = threading.Thread(target=_run, daemon=True)
        with self._lock:
            self._threads[task_id] = t
        t.start()
        return cancel_evt

    def cancel(self, task_id: int) -> bool:
        """设置取消标志。返回 True 表示找到了运行中的任务(对已结束任务幂等返回 False)。"""
        with self._lock:
            evt = self._cancel_flags.pop(task_id, None)
        if evt:
            evt.set()
            return True
        return False

    def is_running(self, task_id: int) -> bool:
        with self._lock:
            return task_id in self._threads
