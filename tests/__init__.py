import pathlib
import json
import unittest

from ruamel.yaml import YAML
yaml = YAML(typ='safe')
yaml.default_flow_style = False

TESTS_DIR = pathlib.Path(__file__).resolve().parent.absolute()
RESOURCES_DIR = TESTS_DIR.joinpath("resources")

class BaseNetParserTest(unittest.TestCase):

    RESOURCES_DIR = TESTS_DIR.joinpath("resources")

    def load_resource_text(self, path: pathlib.Path) -> str:
        data = None
        data = path.read_text()
        return data

    def load_resource_json(self, path: pathlib.Path) -> dict:
        data = None
        data = json.loads(path.read_text())
        return data

    def load_resource_yaml(self, path: pathlib.Path) -> dict:
        data = None
        data = yaml.load(path.read_text())
        return data


    def get_test_resources(self, test_name: str, vendor: str = None):
        if vendor is None:
            if hasattr(self, 'VENDOR'):
                vendor = self.VENDOR
            else:
                msg = "No Vendor Specified"
                raise ValueError(msg)
        vendor_resource_dir = RESOURCES_DIR.joinpath(vendor)
        if not vendor_resource_dir.is_dir():
            msg = f"Path '{vendor_resource_dir}' is not a directory."
            raise NotADirectoryError(msg)
        elif not vendor_resource_dir.exists():
            msg = f"Path '{vendor_resource_dir}' does not exist."
            raise FileNotFoundError(msg)

        data_path = vendor_resource_dir.joinpath("data").joinpath(f"{test_name}.txt")
        results_path = vendor_resource_dir.joinpath("results").joinpath(f"{test_name}.yml")

        for path in [data_path, results_path]:
            if not path.is_file():
                msg = f"Path '{path}' does not exist."
                raise FileNotFoundError(msg)
            elif not path.exists():
                msg = f"Path '{path}' does not exist."
                raise FileNotFoundError(msg)

        return data_path, results_path

    def load_test_resources(self, test_name: str, vendor: str = None):
        data_path, results_path = self.get_test_resources(test_name=test_name, vendor=vendor)

        resources = None
        try:
            resources = {
                "data": self.load_resource_text(data_path),
                "results": self.load_resource_yaml(results_path)
            }
        except Exception as e:
            raise

        return resources
