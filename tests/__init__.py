import pathlib
import json
import unittest

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


    def load_test_resources(self, test_name: str, vendor: str = None):
        if vendor is None:
            if hasattr(self, 'VENDOR'):
                vendor = self.VENDOR
            else:
                msg = "No Vendor Specified"
                raise ValueError(msg)

        vendor_resource_dir = RESOURCES_DIR.joinpath(vendor)
        if not vendor_resource_dir.exists():
            msg = f"Directory '{vendor_resource_dir}' does not exist."
            raise FileNotFoundError(msg)
        elif not vendor_resource_dir.is_dir():
            msg = f"Path '{vendor_resource_dir}' is not a directory."
            raise NotADirectoryError(msg)

        resources = None
        try:
            resources = {
                "data": self.load_resource_text(vendor_resource_dir.joinpath("data").joinpath(f"{test_name}.txt")),
                "results": self.load_resource_json(vendor_resource_dir.joinpath("results").joinpath(f"{test_name}.json"))
            }
        except Exception as e:
            raise

        return resources
