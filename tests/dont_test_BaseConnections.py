import queue
import unittest

from net_parser.utils import get_logger
from net_parser.config import IosConfigParser
from net_parser.connections import BaseConnectionWorker

try:
    from netmiko import ConnectHandler
except ImportError:
    print("Netmiko not installed. Please install via 'pip install netmiko'")

class IosConnectionWorker(BaseConnectionWorker):

    def process_task(self, task):

        with ConnectHandler(**task["handler"]) as device:
            device.enable()
            output = device.send_command('show running-config')
            config = IosConfigParser(config=output, verbosity=5)
            config.DEFAULTS.INTERFACES_DEFAULT_NO_SHUTDOWN = True
            config.DEFAULTS.INTERFACES_DEFAULT_CDP_ENABLED = True
            config.DEFAULTS.INTERFACES_DEFAULT_LLDP_ENABLED = True
            config.parse()
            result = config.to_model().serial_dict(exclude_none=True)
            return result

class BaseConnectionTest(unittest.TestCase):

    def test_01(self):
        task_queue = queue.Queue()
        task_queue.put({
            "host_name": "P01-R1",
            "handler": {
                "ip": "10.17.84.211",
                "device_type": "cisco_ios_telnet",
                "username": "admin",
                "password": "cisco"
            }
        })

        task_queue.put({
            "host_name": "P01-R2",
            "handler": {
                "ip": "10.17.84.212",
                "device_type": "cisco_ios_telnet",
                "username": "admin",
                "password": "cisco"
            }
        })
        result_queue = queue.Queue()
        logger = get_logger(name="TEST-LOGGER", with_threads=True, verbosity=5)
        workers = IosConnectionWorker.worker_factory(task_queue=task_queue, result_queue=result_queue, logger=logger, num_workers=5)
        IosConnectionWorker.start_workers(task_queue=task_queue, workers=workers)
        print(result_queue.qsize())
        results = []
        while True:
            result = None
            try:
                result = result_queue.get_nowait()
                results.append(result)
            except queue.Empty:
                print("Result queue empty")
                break
        for result in results:
            print(result)

if __name__ == '__main__':
    unittest.main()