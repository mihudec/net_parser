import logging
import pathlib
from typing import Union, List

from net_parser.exceptions import *

def check_path(path: pathlib.Path, logger: logging.Logger) -> pathlib.Path:
    if not isinstance(path, pathlib.Path):
        try:
            path = pathlib.Path(path)
        except Exception as e:
            msg = f"Unhandled Exception occured while converting string to path. Exception: {repr(e)}"
            logger.critical(msg=msg)
            raise
    try:
        path = path.resolve()
    except OSError as e:
        msg = "Path syntax is invalid"
        logger.debug(msg=msg)
        raise InvalidPathSyntax(msg)
    except Exception as e:
        msg = f"Unhandled Exception occured while trying to resolve path. Exception: {repr(e)}"
        logger.critical(msg=msg)
        raise
    # If we got here, the path syntax is valid, just check if it exists and is file
    if not path.is_file():
        msg = f"File '{path}' not found."
        # logger.error(msg=msg)
        raise FileNotFoundError(msg)

    return path


def load_text(obj: Union[pathlib.Path, List[str], str], logger: logging.Logger, omit_empty_lines: bool = False) -> List[str]:
    lines = []
    path = None
    # Decide base on type of obj:
    if isinstance(obj, list):
        # Loading object is list
        if not all([isinstance(x, str) for x in obj]):
            msg = "Expected list of str, but not all elements are strings."
            logger.error(msg=msg)
            raise AssertionError(msg)
        else:
            lines = list(obj)
    elif isinstance(obj, str):
        # Might be a path
        try:
            path = check_path(path=obj, logger=logger)
            lines = path.read_text().splitlines()
        except FileNotFoundError as e:
            path = None
            lines = obj.splitlines()
        except InvalidPathSyntax as e:
            path = None
            lines = obj.splitlines()

    elif isinstance(obj, pathlib.Path):
        try:
            path = check_path(path=obj, logger=logger)
            lines = path.read_text().splitlines()
        except FileNotFoundError as e:
            msg = f"Got path to load, but the path does not exist. Path: {obj}"
            logger.critical(msg=msg)
            raise
    logger.debug(f"Loaded {len(lines)} lines.")
    return lines


def first_candidate_or_none(candidates: list, logger: logging.Logger, wanted_type=None):
    if len(candidates) == 0:
        return None
    elif len(candidates) == 1:
        if wanted_type is None:
            return candidates[0]
        else:
            return wanted_type(candidates[0])
    else:
        logger.error(msg='Multiple candidates found.')
        return None
