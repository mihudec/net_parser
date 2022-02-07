import pathlib
import re
import timeit
import warnings
from typing import Union, List, Type
from net_parser.utils import get_logger, load_text, first_candidate_or_none, compile_regex, match_to_dict, property_autoparse, re_search_lines
from net_parser.config import BaseConfigLine

from net_models.inventory import ConfigDefaults

re._MAXCACHE = 1024


class BaseConfigParser(object):

    PATTERN_TYPE = type(re.compile(pattern=""))
    CONFIG_LINE_CLS = BaseConfigLine

    def __init__(self, config: Union[pathlib.Path, List[str], str], verbosity: int = 4, name: str = "BaseConfigParser", defaults: Type[ConfigDefaults] = None, **kwargs):
        """
        Base class for parsing Cisco-like configs

        Args:
            config (:obj:`pathlib.Path` or `str` or `list`): Config file in a form of `pathlib.Path`, or `string`
                containing the entire config or list of lines of the config file
            verbosity (:obj:`int`, optional): Determines the verbosity of logging output, defaults to 4: Info

        Attributes:
            lines (list): Contains list of all config lines stored as objects (see :class:`ccutils.ccparser.BaseConfigLine`)
            config_lines_str (list): Contains list of all config lines stored as strings

        Examples:

            Possible config inputs::

                # Using pathlib
                config_file = pathlib.Path("/path/to/config_file.txt")
                config = BaseConfigParser(config=config_file)

                # Using string
                config_string = '''
                hostname RouterA
                !
                interface Ethernet0/0
                 description Test Interface
                 ip address 10.0.0.1 255.255.255.0
                !
                end
                '''
                config = BaseConfigParser(config=config_string)

                # Using list
                config_list = [
                "hostname RouterA",
                    "!",
                    "interface Ethernet0/0",
                    " description Test Interface",
                    " ip address 10.0.0.1 255.255.255.0",
                    "!",
                    "end"
                ]
                config = BaseConfigParser(config=config_list)

        """
        self.verbosity = verbosity
        self.logger = get_logger(name=name, verbosity=verbosity)
        self._config = config
        self.lines: List[BaseConfigLine] = []
        self.DEFAULTS = defaults or ConfigDefaults()


        self._is_parsed: bool = False


    def __iter__(self):
        return iter(self.lines)

    def __repr__(self):
        return f"[{self.__class__.__name__} - {len(self.lines)} lines]"

    def __str__(self):
        return self.__repr__()

    def to_str(self):
        return '\n'.join(map(lambda x: x.text, self.lines))

    def load_config(self) -> List[str]:
        raw_lines = load_text(obj=self._config, logger=self.logger)
        return raw_lines

    def parse(self):
        """
        Entry function which triggers the parsing process. Called automatically when instantiating the object.

        :return: ``None``
        """
        raw_config_lines = self.load_config()
        self.config_lines_str = raw_config_lines
        self.fix_indents()
        self._create_cfg_line_objects()
        self._is_parsed = True

    def _check_path(self, filepath):
        path = None
        if not isinstance(filepath, pathlib.Path):
            path = pathlib.Path(filepath)
        else:
            path = filepath
        path = path.resolve()
        if not path.exists():
            self.logger.error(msg="Path '{}' does not exist.".format(filepath))
            return None
        if not path.is_file():
            self.logger.error(msg="Path '{}' is not a file.".format(filepath))
        if not path.is_absolute():
            path = path.resolve()
            self.logger.debug("Path '{}' is existing file.".format(filepath))
            return path
        else:
            self.logger.debug("Path '{}' is existing file.".format(filepath))
            return path

    def _get_indent(self, line):
        indent_size = len(line) - len(line.lstrip(" "))
        return indent_size

    # Deprecated
    def _get_clean_config(self, first_line_regex=r"^version \d+\.\d+", last_line_regex=r"^end"):
        self.logger.debug(msg="Cleaning config lines")
        first_regex = re.compile(pattern=first_line_regex, flags=re.MULTILINE)
        last_regex = re.compile(pattern=last_line_regex, flags=re.MULTILINE)
        first = None
        last = None
        for i in range(len(self.config_lines_str)):
            if not first:
                if re.match(pattern=first_regex, string=all_lines[i]):
                    first = i
                    self.logger.debug(msg="Found first config line: '{}'".format(all_lines[first]))
            if not last:
                if re.match(pattern=last_regex, string=all_lines[i]):
                    last = i
                    self.logger.debug(msg="Found last config line: '{}'".format(all_lines[last]))
                    break
        if not first or not last:
            self.config_lines_str = []
            self.logger.error(msg="No valid config found!")
        else:
            self.config_lines_str = all_lines[first:last + 1]
            self.logger.info(msg="Loading {} config lines.".format(len(self.config_lines_str)))
        # Fix indent

    def fix_indents(self):
        """
        Function for fixing the indentation level of config lines.

        :return:
        """
        indent_map = list(map(self._get_indent, self.config_lines_str))
        fixed_indent_map = []
        for i in range(len(indent_map)):
            if i == 0:
                ### Assume the first line is not indented
                fixed_indent_map.append(0)
                continue
            if indent_map[i] == 0:
                fixed_indent_map.append(0)
                continue
            # If indent is same preceding line, copy its indent
            if indent_map[i] == indent_map[i-1]:
                fixed_indent_map.append(fixed_indent_map[-1])
            # If indent is higher that preceding line, increase by one
            elif indent_map[i] > indent_map[i-1]:
                fixed_indent_map.append(fixed_indent_map[-1]+1)
            # If indent is lower that preceding line
            elif indent_map[i] < indent_map[i-1]:
                fixed_indent_map.append(fixed_indent_map[-1]-1)
        for i, val in enumerate(fixed_indent_map):
            self.config_lines_str[i] = " "*val + self.config_lines_str[i].strip()
            #print(val, "'{}'".format(self.config_lines_str[i]))

    def _create_cfg_line_objects(self):
        """
        Function for generating ``self.lines``.

        """
        start = timeit.default_timer()
        # Empty self.lines
        self.lines = [None] * len(self.config_lines_str)
        for number, text in enumerate(self.config_lines_str):
            self.lines[number] = self.CONFIG_LINE_CLS(number=number, text=text, config=self, verbosity=self.verbosity).return_obj()
        for line in self.lines:
            line.type = line.get_type
        self.logger.debug(msg="Created {} ConfigLine objects in {} ms.".format(len(self.lines), (timeit.default_timer()-start)*1000))

    def _compile_regex(self, regex, flags=re.MULTILINE):
        """
        Helper function for compiling `re` patterns from string.

        :param str regex: Regex string
        :param flags: Flags for regex pattern, default is re.MULTILINE
        :return:
        """
        pattern = None
        try:
            pattern = re.compile(pattern=regex, flags=flags)
        except Exception as e:
            self.logger.error(msg="Error while compiling regex '{}'. Exception: {}".format(regex, repr(e)))
        return pattern

    def find_objects(self, regex, flags=re.MULTILINE, group: Union[int, str, None] = None):

        warnings.warn(message=f"You are using a deprecated method 'find_objects'. Please switch to using 're_search_lines'.")
        results = self.re_search_lines(regex=regex, group=group)
        return results

    def get_section_by_parents(self, parents):
        if not isinstance(parents, list):
            parents = list(parents)
        section = list(self.lines)
        for parent in parents:
            section = [x.get_children() for x in section if bool(x.is_parent and x.re_match(parent))]
            if len(section) == 1:
                section = section[0]
            elif len(section) > 1:
                self.logger.error("Multiple lines matched parent statement. Cannot determine config section.")
                return []
            else:
                self.logger.error("No lines matched parent statement. Cannot determine config section.")
                return []
        return section

    def match_to_dict(self, line, patterns):
        return match_to_dict(line=line, regexes=patterns)

    def property_autoparse(self, candidate_pattern, patterns):
        return property_autoparse(lines=self.lines, candidate_pattern=candidate_pattern, regexes=patterns, logger=self.logger, include_candidate=True)

    def section_property_autoparse(self, parent, patterns, return_with_line=False):
        entries = None
        if isinstance(parent, BaseConfigLine):
            candidates = [parent]
        elif isinstance(parent, (str, self.PATTERN_TYPE)):
            candidates = self.re_search_lines(regex=parent)
        if len(candidates):
            entries = []
        else:
            return entries
        for candidate in candidates:
            entry = {}
            if isinstance(parent, (str, self.PATTERN_TYPE)):
                entry.update(self.match_to_dict(line=candidate, patterns=[parent]))
            for pattern in patterns:
                updates = candidate.re_search_children(regex=pattern, group="ALL")
                if len(updates) == 1:
                    entry.update(updates[0])
                elif len(updates) == 0:
                    entry.update({k: None for k in pattern.groupindex.keys()})
                else:
                    self.logger.warning("Multiple possible updates found for Pattern: '{}' on Candidate: '{}'".format(pattern, candidate))
            if return_with_line:
                entries.append((candidate, entry))
            else:
                entries.append(entry)
        return entries

    def compile_regex(self, pattern: str, flags=re.MULTILINE):
        return compile_regex(pattern=pattern, flags=flags, logger=self.logger, raise_exc=True)

    def _val_to_bool(self, entry: dict, keys: list):
        if not isinstance(keys, list):
            keys = list(keys)
        for key in keys:
            if entry[key]:
                entry[key] = True
            else:
                entry[key] = False
        return entry

    def first_candidate_or_none(self, candidates: list, wanted_type=None):
        return first_candidate_or_none(candidates=candidates, logger=self.logger, wanted_type=wanted_type)

    def re_search_lines(self, regex: re.Pattern, group: str = None) -> List[Union[str, dict, 'BaseConfigLine']]:
        results = re_search_lines(lines=self.lines, regex=regex, group=group)
        self.logger.debug(msg="Matched {} lines for query '{}'".format(len(results), regex))
        return results

    def get_formal(self):
        formal_config_lines = []
        for line in self.lines:
            if line.is_comment:
                continue
            formal_line = ""
            parents = line.get_parents()
            # print(f"{parents=} {line=}")
            if len(parents):
                formal_line += (" ".join([x.text.lstrip(' ') for x in parents]) + " ")
            formal_line += line.text.strip(" ")
            # print(formal_line)
            formal_config_lines.append(formal_line)
        # print(formal_config_lines)
        return formal_config_lines
