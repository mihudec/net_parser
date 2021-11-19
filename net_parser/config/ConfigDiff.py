
from pydantic.typing import (
    Dict, List, Literal, Optional, Union, Type
)

from net_parser.utils import get_logger, first_candidate_or_none, raw_match_lines, PATTERN_TYPE, assert_is_regex
from net_parser.config import BaseConfigParser, BaseConfigLine


__all__ = [
    'DiffedLine',
    'ConfigDiff',
    'ConfigDiff',
    'IosConfigDiff'
]

class DiffedLine:

    def __init__(self, text, action: Literal['add', 'remove', 'present']):
        self.text = text
        self.action = action

    def __str__(self):
        return self.text

    def __repr__(self):
        sign_map = {
            'add': '+',
            'remove': '-',
            'present': '='
        }
        return f"{sign_map[self.action]} {self.text}"


class ConfigDiff:
    _registry = {}

    def __init_subclass__(cls, **kwargs):
        device_type = kwargs.pop('device_type', None)
        if device_type is not None:
            cls._registry[device_type] = cls
        super().__init_subclass__(**kwargs)

    def __new__(cls, *args, **kwargs):
        device_type = kwargs.pop('device_type', None)
        subclass = None
        if device_type is not None:
            subclass = cls._registry.get(device_type, None)
        if subclass is None:
            subclass = cls
        obj = object.__new__(subclass)
        obj.__init__(**kwargs)
        return obj


    DEFAULT_IGNORE_LINES = []

    def __init__(self,
                 first: BaseConfigParser,
                 second: BaseConfigParser,
                 verbosity: int = 4,
                 **kwargs):
        self.logger = get_logger(name='ConfigDiff', verbosity=verbosity)
        self.first = first
        self.second = second
        self._check_configs()

    def _check_configs(self):
        for i, config in enumerate([self.first, self.second]):
            if not isinstance(config, BaseConfigParser):
                msg = f"Config {'first' if i == 0 else 'second'} has to be an instance of 'BaseConfigParser', got {type(self.first)=}"
                self.logger.critical(msg=msg)
                raise TypeError(msg)

    def add_line(self, line):
        return DiffedLine(text=line.text, action='add')

    def remove_line(self, line):
        return DiffedLine(text=line.text, action='remove')

    def present_line(self, line):
        return DiffedLine(text=line.text, action='present')

    def is_ignore_line(self, line: BaseConfigLine, diff_ignore: List[PATTERN_TYPE] = None) -> bool:
        ignore = False
        diff_ignore = diff_ignore or self.DEFAULT_IGNORE_LINES
        if not isinstance(diff_ignore, list):
            diff_ignore = [diff_ignore]
        diff_ignore = [assert_is_regex(x) for x in diff_ignore]
        if len(diff_ignore) == 0:
            return False
        else:
            ignore = any([bool(x.match(string=line.text)) for x in diff_ignore])
        if ignore:
            self.logger.info(msg=f"Ignored line: {line}")
        return ignore

    def diff_line(self, line: BaseConfigLine, other_lines: List[BaseConfigLine], diff_ignore: List[PATTERN_TYPE] = None):
        if 'comment' in line.get_type:
            return []
        if self.is_ignore_line(line=line, diff_ignore=diff_ignore):
            return []
        updates = []

        candidates = raw_match_lines(lines=other_lines, text=line.text)
        first_candidate = first_candidate_or_none(candidates=candidates[:1])
        if first_candidate is None:
            updates.append(self.add_line(line))
            if line.is_parent:
                updates.extend([self.add_line(x) for x in line.get_children()])
        elif line.is_parent and not first_candidate.is_parent:
            updates.append(self.present_line(first_candidate))
            # Add all children to update
            updates.extend([self.add_line(x) for x in line.get_children()])
        elif line.is_parent and first_candidate.is_parent:
            line_updates = []
            for child in line.get_children(max_depth=1):
                if self.is_ignore_line(line=child, diff_ignore=diff_ignore):
                    continue
                # For each direct child generate diff and append to updates
                child_updates = self.diff_line(line=child, other_lines=first_candidate.get_children())
                if len(child_updates):
                    line_updates.extend(child_updates)
            if len(line_updates):
                line_updates.insert(0, self.present_line(line))
            updates.extend(line_updates)
        self.logger.debug(msg=f"Returning updates:\n{updates}")
        return updates

    def difference(self, diff_ignore: List[PATTERN_TYPE] = None):
        diff_updates = []
        first_top_lines = [x for x in self.first.lines if x.indent == 0]
        second_top_lines = [x for x in self.second.lines if x.indent == 0]
        for line in second_top_lines:
            line_diff = self.diff_line(line=line, other_lines=first_top_lines, diff_ignore=diff_ignore)
            diff_updates.extend(line_diff)
        return diff_updates

    @staticmethod
    def print_diff(diff_lines: List[DiffedLine]):
        present = len([x for x in diff_lines if x.action == 'present'])
        added = len([x for x in diff_lines if x.action == 'add'])
        removed = len([x for x in diff_lines if x.action == 'remove'])
        print(f"! Diff:\n!\t{present=}\n!\t{added=}\n!\t{removed=}")
        for line in diff_lines:
            print(repr(line))

    @staticmethod
    def get_update_config(diff_lines: List[DiffedLine]):
        return '\n'.join([x.text for x in diff_lines if x.action in ['present', 'add']])

    def __str__(self):
        return f"[{self.__class__.__name__} Object]"


class IosConfigDiff(ConfigDiff, device_type='cisco_ios'):

    pass
