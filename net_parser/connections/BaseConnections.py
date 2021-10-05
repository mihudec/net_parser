import threading
import queue
import sys
import time
import logging


from net_parser.utils import get_logger

class BaseConnectionWorker(threading.Thread):

    def __init__(self, task_queue: queue.Queue, logger: logging.Logger = None, result_queue: queue.Queue = None, name: str = None, _name: str = "BaseConnectionWorker"):
        self.logger = logger or get_logger(name=_name)
        self.logger.debug(msg=f"Worker spawned.")
        self.shutdown_flag = threading.Event()
        self.task_queue = task_queue
        self.result_queue = result_queue
        super().__init__(name=name)

    def shutdown(self):
        self.logger.info(msg=f"Received Shutdown event - exiting.")
        self.shutdown_flag.set()

    def run(self):
        while not self.shutdown_flag.is_set():
            try:
                task = self.task_queue.get(block=True, timeout=1)
            except queue.Empty:
                self.logger.info(msg="Task Queue empty - exiting.")
                break

            if task is None:
                self.logger.warning(msg="Received None task - exiting.")
                break

            result = self.process_task(task=task)
            self.task_queue.task_done()
            self.logger.debug(msg=f"Finished task, result: {result}")
            if self.result_queue is not None:
                self.result_queue.put(result)

    def process_task(self, task):
        self.logger.debug(msg=f"Received task: {task}")
        return {"result": None}

    @classmethod
    def worker_factory(cls, task_queue: queue.Queue, result_queue: queue.Queue = None, logger: logging.Logger = None, num_workers: int = 5):
        workers = []
        for i in range(num_workers):
            worker = cls(name="WorkerThread-{}".format(i), task_queue=task_queue, result_queue=result_queue, logger=logger)
            workers.append(worker)
        return workers

    @classmethod
    def start_workers(cls, task_queue, workers):
        [w.start() for w in workers]
        while True:
            try:
                time.sleep(0.1)
                if task_queue.empty():
                    break
            except KeyboardInterrupt as e:
                [w.shutdown() for w in workers]
                sys.exit(1)
        task_queue.join()
