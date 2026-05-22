"""StackItem – the value trackable on the virtual operand stack."""
import json


class StackItem:
    __slots__ = ('type', 'name', 'value', 'script')

    def __init__(self, tp='undefined', name=None, value=None, script=None):
        self.type = tp
        self.name = name
        self.value = value
        self.script = script

    def get_value(self):
        if self.script is not None:
            return self.script
        if self.name is not None:
            return self.name
        if self.type == 'string':
            return json.dumps(self.value)
        if self.type == 'number' and self.value is not None:
            s = str(self.value)
            if s.endswith('.0'):
                s = s[:-2]
            return s
        if self.type == 'boolean':
            return 'true' if self.value else 'false'
        if self.type in ('null', 'undefined', 'void'):
            return self.type
        if self.type == 'function':
            if self.value and '__FN_' in str(self.value):
                return str(self.value)
            return '(function(){/* nested */})'
        if self.type == 'regexp' and self.value:
            return str(self.value)
        if self.type == 'object':
            return '{}'
        if self.type == 'array':
            return '[]'
        return str(self.value) if self.value is not None else 'undefined'

    def copy(self):
        return {
            'tp': self.type,
            'name': self.name,
            'value': self.value,
            'script': self.script,
        }
