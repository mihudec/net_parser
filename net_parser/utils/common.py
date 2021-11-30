import functools
import logging
import pathlib
import re
from pydantic.typing import Union, List, Tuple, Type, Dict

from net_parser.exceptions import *
from .get_logger import get_logger

PATTERN_TYPE = type(re.compile(pattern=""))

LOGGER = get_logger(name="CommonLogger", verbosity=4)

EMPTY_LINE_REGEX = re.compile(pattern=r'^\s*$')
NOT_EMPTY_LINE_REGEX = re.compile(pattern=r'.*\S.*')

def check_path(path: pathlib.Path, logger: logging.Logger) -> pathlib.Path:
    if not isinstance(path, pathlib.Path):
        try:
            path = pathlib.Path(path)
        except (OSError, ValueError) as e:
            msg = "Path syntax is invalid"
            logger.debug(msg=msg)
            raise InvalidPathSyntax(msg)
        except Exception as e:
            msg = f"Unhandled Exception occured while converting string to path. Exception: {repr(e)}"
            logger.critical(msg=msg)
            raise
    try:
        path = path.resolve()
    except (OSError, ValueError) as e:
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


def load_text(obj: Union[pathlib.Path, List[str], str], logger: logging.Logger = None, omit_empty_lines: bool = False) -> List[str]:
    logger = logger or LOGGER
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
        try:
            path = check_path(path=obj, logger=logger)
            lines = path.read_text().splitlines()
        except FileNotFoundError as e:
            path = None
            lines = obj.splitlines()
        except InvalidPathSyntax as e:
            path = None
            lines = obj.splitlines()
        except Exception as e:
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
    all_lines = len(lines)
    lines = [x.rstrip() for x in lines if not EMPTY_LINE_REGEX.match(x)]
    empty_lines = all_lines - len(lines)
    logger.debug(f"Loaded {len(lines)} lines. {empty_lines} were empty.")
    return lines


def first_candidate_or_none(candidates: list, logger: logging.Logger = None, wanted_type=None):
    logger = logger or LOGGER
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

@functools.lru_cache(maxsize=512)
def compile_regex(pattern: str, logger: logging.Logger = None, flags=re.MULTILINE, raise_exc=True) -> Type[PATTERN_TYPE]:
    """
    Wrapper around re.compile with some defaults and error handling.

    Args:
        pattern: Regular Expression string.
        logger: Instance of logging.Logger, if not provided, default logger will be used.
        flags: Flags for the re.compile, uses `re.MULTILINE` by default.
        raise_exc: Wether or not to raise exception of re.compile fails. Default is True.

    Returns: A compiled pattern

    """
    logger = logger or LOGGER
    compiled_regex = None
    try:
        compiled_regex = re.compile(pattern=pattern, flags=flags)
    except Exception as e:
        logger.error(msg=f"Error while compiling regex '{compiled_regex}'. Exception: {repr(e)}")
        if raise_exc:
            raise
        else:
            compiled_regex = None
    return compiled_regex


def assert_is_regex(regex) -> PATTERN_TYPE:
    """
    Try to make sure that `regex` is actually a re.compile-d patter. If not, make it so.

    Args:
        regex: Expects either compiled patter or string.

    Returns: Compiled pattern

    """
    if isinstance(regex, PATTERN_TYPE):
        return regex
    else:
        return compile_regex(pattern=regex, raise_exc=True)

def re_search(line: 'BaseConfigLine', regex: re.Pattern, group: str = None):
    """
    Search config line for given regex

    Args:
        regex (:obj:`re.Pattern` or ``str``): Regex to search for
        group (:obj:`str` or ``int``, optional): Return only specific (named or numbered) group of given regex.
            If set to "ALL", return value will be a dictionary with all named groups of the regex.

    Examples:

        Example::

            # Given the following line stored in `line` variable
            # " ip address 10.0.0.1 255.255.255"
            pattern = r"^ ip address (?P<ip>\S+) (?P<mask>\S+)"

            # Basic search
            result = line.re_search(regex=pattern)
            print(result)
            # Returns: " ip address 10.0.0.1 255.255.255"

            # Search for specific group
            result = line.re_search(regex=pattern, group="ip")
            print(result)
            # Returns: "10.0.0.1"

            # Get all named groups
            result = line.re_search(regex=pattern, group="ALL")
            print(result)
            # Returns: {"ip": "10.0.0.1", "mask": "255.255.255"}


    Returns:
        str: String that matched given regex, or, if `group` was provided, returns only specific group.

        Returns ``None`` if regex did not match.

    """
    logger = line.logger
    regex = assert_is_regex(regex)

    m = regex.search(string=line.text)
    if m:
        if group is None:
            return m.group(0)
        elif isinstance(group, int):
            if group <= regex.groups:
                return m.group(group)
            else:
                logger.error(msg="Given regex '{}' does not contain required group '{}'".format(regex, group))
                return None
        elif isinstance(group, str):
            if group in regex.groupindex.keys():
                return m.group(group)
            elif group == "ALL":
                return m.groupdict()

            else:
                logger.error(msg="Given regex '{}' does not contain required group '{}'".format(regex, group))
                return None
    else:
        logger.debug(msg="Given regex '{}' did not match.".format(regex))
        return None

def match_to_dict(line: Type['BaseConfigLine'], regexes: List[Type[PATTERN_TYPE]]) -> dict:
    """
    Match multiple regexes against sigle line and return a dictionary with all the named groups
    contained in all regexes.

    Args:
        line: Instance of BaseConfigLine and its subclasses
        regexes: List of regexes to match against the line

    Returns: A flat dictionary where keys are named groups from the regexes.

    """
    entry = {}
    for regex in regexes:
        regex = assert_is_regex(regex)
        match_result = line.re_search(regex=regex, group="ALL")
        if match_result is not None:
            entry.update(match_result)
        else:
            entry.update({k: None for k in regex.groupindex.keys()})
    return entry



def re_search_lines(lines: List['BaseConfigLine'], regex: re.Pattern, group: str = None) -> List[Union[str, dict, 'BaseConfigLine']]:
    regex = assert_is_regex(regex)
    result = list(filter(lambda x: bool(regex.search(string=x.text)), lines))
    if group is not None:
        result = [x.re_search(regex=regex, group=group) for x in result]
    return result

def raw_match_lines(lines: List[Type['BaseConfigLine']], text: str) -> List[Type['BaseConfigLine']]:
    results = [x for x in lines if x.text == text]
    return results

def re_filter_lines(lines: List['BaseConfigLine'], regex: re.Pattern, group: str = None, pop_matches: bool = True) -> Tuple[list, list]:
    regex = assert_is_regex(regex)
    result = re_search_lines(lines=lines, regex=regex, group=None)
    if pop_matches:
        lines = sorted(list(set(lines).difference(set(result))), key=lambda x: x.number)
    if group is not None:
        result = [x.re_search(regex=regex, group=group) for x in result]
    return result, lines

def re_match(line: 'BaseConfigLine', regex, group=None) -> List[Union[str, dict, Type['BaseConfigLine']]]:
    logger = line.logger
    regex = assert_is_regex(regex)

    if regex is None:
        return None
    m = regex.match(string=line.text)
    if m:
        if group is None:
            return m.group(0)
        elif isinstance(group, int):
            if group <= regex.groups:
                return m.group(group)
            else:
                logger.error(msg="Given regex '{}' does not contain required group '{}'".format(regex, group))
                return None
        elif isinstance(group, str):
            if group in regex.groupindex.keys():
                return m.group(group)
            elif group == "ALL":
                return m.groupdict()
            else:
                logger.error(msg="Given regex '{}' does not contain required group '{}'".format(regex, group))
                return None
    else:
        logger.debug(msg="Given regex '{}' did not match.".format(regex))
        return None


def property_autoparse(lines: List['BaseConfigLine'], candidate_pattern: re.Pattern, regexes: List[re.Pattern], logger: logging.Logger = None, include_candidate: bool = True) -> List[Dict]:
    logger = logger or LOGGER
    properties = []
    candidates = re_search_lines(lines=lines, regex=candidate_pattern)
    if not len(candidates):
        return properties
    if include_candidate and candidate_pattern not in regexes:
        regexes.insert(0, candidate_pattern)
    for candidate in candidates:
        properties.append(match_to_dict(line=candidate, regexes=regexes))
    return properties