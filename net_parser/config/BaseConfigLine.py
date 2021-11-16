import pathlib
import re
import json
import timeit
import functools


from net_parser.utils import get_logger, first_candidate_or_none, re_search, re_search_lines, re_match, PATTERN_TYPE, compile_regex


class BaseConfigLine(object):

    PATTERN_TYPE = PATTERN_TYPE
    _parent_indent_regex = re.compile(pattern=r"[^! ]", flags=re.MULTILINE)
    _interface_regex = re.compile(pattern=r"^interface\s(\S+)", flags=re.MULTILINE)
    comment_regex = re.compile(pattern=r"^\s*!.*", flags=re.MULTILINE)

    def __init__(self, number, text, config: 'BaseConfigParser', verbosity=3, name="BaseConfigLine"):
        """
        **This class is not meant to be instantiated directly, but only from BaseConfigParser instance.**

        Args:
            number (int): Index of line in config
            text (str): Text of the config line
            config (:obj:`BaseConfigParser`): Reference to the parent BaseConfigParser object
            verbosity (:obj:`int`, optional): Logging output level, defaults to 3: Warning

        """
        self._name = name
        self.logger = get_logger(name=name, verbosity=verbosity)
        #print(self.logger.handlers)
        self.config = config
        self.config_lines_obj = self.config.lines
        self.number = number
        self.text = text
        self.indent = len(self.text) - len(self.text.lstrip(" "))
        self.type = None
        # self.logger.debug("Parsing line: #{}: '{}'".format(self.number, self.text))


    def return_obj(self):
        return self

    # def __eq__(self, other) -> bool:
    #     return self.get_line == other.get_line

    # def __ne__(self, other) -> bool:
    #     return not self.__eq__(other)

    def compile_regex(self, pattern: str, flags=re.MULTILINE):
        return compile_regex(pattern=pattern, flags=flags, logger=self.logger, raise_exc=True)

    def get_children(self, max_depth: int = None):
        """
        Return all children lines (all following lines with larger indent)

        Returns:
            list: List of child config lines (objects)

        """
        children = []
        line_num = int(self.number) + 1
        #print(len(self.config.lines))
        while line_num <= len(self.config.lines) - 1:   # Avoid IndexError
            if self.config.lines[line_num].indent <= self.indent:
                break
            else:
                if max_depth and self.config.lines[line_num].indent > self.indent + max_depth:
                    pass
                else:
                    children.append(self.config.lines[line_num])
                line_num += 1
        return children

    @property
    def parent(self):
        if not self.is_child:
            self.logger.debug("Line is not a child, therefore has no parent. Line: {}".format(self.text))
            return None
        else:
            line_num = int(self.number) - 1
            line = self.config.lines[line_num]
            while line.indent >= self.indent and line_num > 0:
                line_num -= 1
                line = self.config.lines[line_num]
            return line

    @functools.lru_cache()
    def get_parents(self):
        start = timeit.default_timer()
        parents = []
        if not self.is_child:
            self.logger.debug("Line is not a child, therefore has no parent. Line: {}".format(self.text))
            pass
        else:
            parents.insert(0, self.parent)
            while parents[0].parent is not None:
                parents.insert(0, parents[0].parent)
        stop = timeit.default_timer()
        self.logger.debug("Getting parents of line {} took {} ms".format(str(self), (stop-start)*10e3))
        return parents

    @property
    def get_path(self):
        path = [x.text for x in self.get_parents()]
        if len(path):
            return path
        else:
            return None

    @property
    def get_line(self):
        line = None
        if self.get_path is not None:
            line = list(self.get_path)
        else:
            line = list()
        line.append(self.text)
        return line


    def re_search_children(self, regex, group=None):
        """
        Search all children for given regex.

        Args:
            regex (:obj:`re.Pattern` or ``str``): Regex to search for
            group (:obj:`str` or ``int``, optional): Return only specific (named or numbered) group of given regex.
                If set to "ALL", return value will be a dictionary with all named groups of the regex.

        Returns:
            list: List of all child object which match given regex, or, if `group` was provided, returns
            list containing matched group across all children.

                Example::

                    # Given following config section, interface line stored in `line` variable
                    config = '''
                    interface Ethernet0/0
                     description Test Interface
                     ip address 10.0.0.1 255.255.255.0
                     ip address 10.0.1.1 255.255.255.0 secondary
                    !
                    '''
                    pattern = r"^ ip address (?P<ip>\S+) (?P<mask>\S+)"

                    result = line.re_search_children(regex=pattern)
                    print(result)
                    # Returns: [
                    #   [BaseConfigLine #2 (child): ip address 10.0.0.1 255.255.255.0],
                    #   [BaseConfigLine #3 (child): ip address 10.0.1.1 255.255.255.0 secondary]
                    # ]

                    result = line.re_search_children(regex=pattern, group="ip")
                    print(result)
                    # Returns: [
                    #   "10.0.0.1",
                    #   "10.0.1.1"
                    # ]

                    result = line.re_search_children(regex=pattern, group="ALL")
                    print(result)
                    # Returns: [
                    #   {"ip": "10.0.0.1", "mask": "255.255.255.0"},
                    #   {"ip": "10.0.1.1", "mask": "255.255.255.0"}
                    # ]


        """
        pattern = None
        if not isinstance(regex, self.PATTERN_TYPE):
            pattern = self.compile_regex(pattern=regex)
        else:
            pattern = regex
        if not pattern:
            return []
        children = self.get_children()
        return re_search_lines(lines=children, regex=regex, group=group)

    # TODO: Add Tests
    # TODO: Add Examples
    def re_search_children_multipattern(self, regexes: list, group=None, deduplicate: bool = True) -> list:
        """
        Wrapper function for ``self.re_search_children()`` allowing to use multiple patterns

        Args:
            regexes (``list``): List of patterns to search
            group (``str`` or ``int``, optional): Return only specific (named or numbered) group of given regex.
                If set to "ALL", return value will be a dictionary with all named groups of the regex.
            deduplicate (``bool``, optional): When set to ``True`` (default), results will not contain duplicate line objects in
                cases where multiple patterns match the same line.

        Returns:
            list: List of all child object which match given regex, or, if `group` was provided, returns
            list containing matched group across all children.

        """
        results = []
        for regex in regexes:
            for result in [x for x in self.re_search_children(regex=regex, group=group)]:
                if result in results:
                    if deduplicate:
                        continue
                    else:
                        results.append(result)
                else:
                    results.append(result)
        return results

    def re_search(self, regex, group=None):
        return re_search(line=self, regex=regex, group=group)

    def re_match(self, regex, group=None):
        return re_match(line=self, regex=regex, group=group)

    @property
    def get_type(self):
        """
        Return `types` of config line. Used mostly for filtering purposes.

        Currently available values are:

        - ``parent``
        - ``child``
        - ``interface``
        - ``comment``

        Returns:
            list: List of types

        """
        types = []
        if re.match(self.comment_regex, self.text):
            types.append("comment")
            # If line is comment, it's comment only
            return types
        if self.is_parent:
            types.append("parent")
        if self.is_child:
            types.append("child")
        return types

    @functools.cached_property
    def is_comment(self):
        return bool(re.match(self.comment_regex, self.text))

    @property
    def is_parent(self):
        """
        Check whether this line is a parent

        Returns:
            bool: True if line is a parent line, False otherwise

        """
        if self.number < len(self.config.lines)-1:
            if self.config.lines[self.number+1].indent > self.indent:
                return True
            else:
                return False
        else:
            return False

    @property
    def is_child(self):
        """
           Check whether this line is a child

           Returns:
               bool: True if line is a child line, False otherwise

           """
        if self.indent > 0:
            return True
        else:
            return False

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

    def __str__(self):
        return f"[{self.__class__.__name__} #{self.number}\t({self.get_type}): '{self.text}']"

    def __repr__(self):
        return self.__str__()


