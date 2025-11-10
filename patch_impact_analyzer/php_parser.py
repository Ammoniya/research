"""PHP code parser for extracting code elements."""

import re
from typing import List, Dict, Set, Optional, Tuple
from .models import (
    FunctionDefinition,
    FunctionCall,
    VariableUsage,
    CodeLocation,
    CodeElement,
    CodeElementType
)


class PHPCodeParser:
    """
    Parser for PHP code to extract functions, calls, variables, and other elements.

    This parser uses regex-based pattern matching since we don't have access to
    a full PHP AST parser. It handles common PHP patterns found in WordPress plugins.
    """

    def __init__(self):
        """Initialize the parser."""
        self.current_file = ""
        self.current_class = None

    def parse_code(self, code: str, file_path: str = "") -> Dict[str, List]:
        """
        Parse PHP code and extract all elements.

        Args:
            code: PHP source code
            file_path: Path to the file being parsed

        Returns:
            Dict containing lists of functions, calls, variables, etc.
        """
        self.current_file = file_path
        self.current_class = None

        return {
            'functions': self.extract_functions(code),
            'calls': self.extract_function_calls(code),
            'variables': self.extract_variables(code),
            'classes': self.extract_classes(code),
            'hooks': self.extract_wordpress_hooks(code)
        }

    def extract_functions(self, code: str) -> List[FunctionDefinition]:
        """
        Extract function definitions from PHP code.

        Args:
            code: PHP source code

        Returns:
            List of FunctionDefinition objects
        """
        functions = []

        # Pattern for function definitions
        # Matches: function name($param1, $param2) {
        # Also handles: public/private/protected function, static, etc.
        pattern = r'(public|private|protected)?\s*(static)?\s*function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\((.*?)\)'

        for match in re.finditer(pattern, code, re.MULTILINE):
            visibility = match.group(1) or "public"
            function_name = match.group(3)
            params_str = match.group(4)

            # Parse parameters
            parameters = []
            if params_str.strip():
                # Extract parameter names (handle $var, Type $var, $var = default)
                param_pattern = r'\$([a-zA-Z_][a-zA-Z0-9_]*)'
                parameters = re.findall(param_pattern, params_str)

            # Get line number
            line_number = code[:match.start()].count('\n') + 1

            # Extract function body
            body = self._extract_function_body(code, match.end())

            # Determine if this is a method (inside a class)
            is_method = self._is_inside_class(code, match.start())
            class_name = self._get_containing_class(code, match.start())

            location = CodeLocation(
                file_path=self.current_file,
                line_number=line_number,
                context=code[max(0, match.start()-50):match.end()+50]
            )

            functions.append(FunctionDefinition(
                name=function_name,
                parameters=parameters,
                location=location,
                body=body,
                is_method=is_method,
                class_name=class_name,
                visibility=visibility
            ))

        return functions

    def extract_function_calls(self, code: str) -> List[FunctionCall]:
        """
        Extract function calls from PHP code.

        Args:
            code: PHP source code

        Returns:
            List of FunctionCall objects
        """
        calls = []

        # Pattern for function calls
        # Matches: function_name($arg1, $arg2)
        pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\('

        # Pattern for method calls
        # Matches: $object->method($args) or Class::method($args)
        method_pattern = r'([\$a-zA-Z_][a-zA-Z0-9_]*)\s*(?:->|::)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\('

        # Extract regular function calls
        for match in re.finditer(pattern, code):
            function_name = match.group(1)

            # Skip language constructs and keywords
            if function_name in ['if', 'while', 'for', 'foreach', 'switch', 'catch', 'function', 'class']:
                continue

            line_number = code[:match.start()].count('\n') + 1

            # Try to extract arguments (simplified)
            args = self._extract_call_arguments(code, match.end() - 1)

            location = CodeLocation(
                file_path=self.current_file,
                line_number=line_number,
                context=code[max(0, match.start()-30):match.end()+30]
            )

            calls.append(FunctionCall(
                name=function_name,
                arguments=args,
                location=location,
                is_method_call=False
            ))

        # Extract method calls
        for match in re.finditer(method_pattern, code):
            object_name = match.group(1)
            method_name = match.group(2)

            line_number = code[:match.start()].count('\n') + 1

            args = self._extract_call_arguments(code, match.end() - 1)

            location = CodeLocation(
                file_path=self.current_file,
                line_number=line_number,
                context=code[max(0, match.start()-30):match.end()+30]
            )

            calls.append(FunctionCall(
                name=method_name,
                arguments=args,
                location=location,
                is_method_call=True,
                object_name=object_name
            ))

        return calls

    def extract_variables(self, code: str) -> List[VariableUsage]:
        """
        Extract variable usages from PHP code.

        Args:
            code: PHP source code

        Returns:
            List of VariableUsage objects
        """
        variables = []

        # Pattern for variable assignments
        # Matches: $var = value
        assignment_pattern = r'\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^;]+);'

        for match in re.finditer(assignment_pattern, code):
            var_name = match.group(1)
            value = match.group(2).strip()

            line_number = code[:match.start()].count('\n') + 1

            location = CodeLocation(
                file_path=self.current_file,
                line_number=line_number,
                context=code[max(0, match.start()-30):match.end()+30]
            )

            variables.append(VariableUsage(
                name=var_name,
                is_write=True,
                location=location,
                value=value
            ))

        # Pattern for variable reads (simplified - just $var usage)
        read_pattern = r'\$([a-zA-Z_][a-zA-Z0-9_]*)'

        seen_reads = set()
        for match in re.finditer(read_pattern, code):
            var_name = match.group(1)

            # Skip if this is an assignment (already captured)
            before_text = code[max(0, match.start()-5):match.start()]
            if '=' in before_text and '->' not in before_text:
                continue

            line_number = code[:match.start()].count('\n') + 1
            key = (var_name, line_number)

            if key not in seen_reads:
                seen_reads.add(key)

                location = CodeLocation(
                    file_path=self.current_file,
                    line_number=line_number,
                    context=code[max(0, match.start()-30):min(len(code), match.end()+30)]
                )

                variables.append(VariableUsage(
                    name=var_name,
                    is_write=False,
                    location=location
                ))

        return variables

    def extract_classes(self, code: str) -> List[str]:
        """
        Extract class names from PHP code.

        Args:
            code: PHP source code

        Returns:
            List of class names
        """
        classes = []

        # Pattern for class definitions
        pattern = r'class\s+([a-zA-Z_][a-zA-Z0-9_]*)'

        for match in re.finditer(pattern, code):
            class_name = match.group(1)
            classes.append(class_name)

        return classes

    def extract_wordpress_hooks(self, code: str) -> List[Dict[str, str]]:
        """
        Extract WordPress hooks (actions and filters).

        Args:
            code: PHP source code

        Returns:
            List of hook information dicts
        """
        hooks = []

        # Pattern for add_action and add_filter
        hook_pattern = r'(add_action|add_filter)\s*\(\s*[\'"]([^\'"]+)[\'"],\s*[\'"]?([^\'")\s,]+)[\'"]?'

        for match in re.finditer(hook_pattern, code):
            hook_type = match.group(1)
            hook_name = match.group(2)
            callback = match.group(3)

            line_number = code[:match.start()].count('\n') + 1

            hooks.append({
                'type': hook_type,
                'name': hook_name,
                'callback': callback,
                'line': line_number
            })

        return hooks

    def _extract_function_body(self, code: str, start_pos: int) -> str:
        """
        Extract function body by matching braces.

        Args:
            code: Full source code
            start_pos: Position where function definition ends (after closing paren)

        Returns:
            Function body as string
        """
        # Find opening brace
        brace_start = code.find('{', start_pos)
        if brace_start == -1:
            return ""

        # Count braces to find matching closing brace
        brace_count = 1
        pos = brace_start + 1

        while pos < len(code) and brace_count > 0:
            if code[pos] == '{':
                brace_count += 1
            elif code[pos] == '}':
                brace_count -= 1
            pos += 1

        if brace_count == 0:
            return code[brace_start:pos]
        return ""

    def _is_inside_class(self, code: str, position: int) -> bool:
        """
        Check if a position is inside a class definition.

        Args:
            code: Source code
            position: Position to check

        Returns:
            True if inside a class
        """
        # Look backward for class definition
        before = code[:position]
        class_pattern = r'class\s+([a-zA-Z_][a-zA-Z0-9_]*)'

        # Find all class definitions before this position
        classes = list(re.finditer(class_pattern, before))

        if not classes:
            return False

        # Check if we're still inside the last class (crude check)
        last_class = classes[-1]
        class_start = last_class.end()

        # Count braces between class start and current position
        code_section = code[class_start:position]
        open_braces = code_section.count('{')
        close_braces = code_section.count('}')

        return open_braces > close_braces

    def _get_containing_class(self, code: str, position: int) -> Optional[str]:
        """
        Get the name of the class containing this position.

        Args:
            code: Source code
            position: Position to check

        Returns:
            Class name or None
        """
        if not self._is_inside_class(code, position):
            return None

        before = code[:position]
        class_pattern = r'class\s+([a-zA-Z_][a-zA-Z0-9_]*)'

        classes = list(re.finditer(class_pattern, before))
        if classes:
            return classes[-1].group(1)

        return None

    def _extract_call_arguments(self, code: str, start_pos: int) -> List[str]:
        """
        Extract function call arguments (simplified).

        Args:
            code: Source code
            start_pos: Position of opening parenthesis

        Returns:
            List of argument strings
        """
        # Find matching closing parenthesis
        paren_count = 1
        pos = start_pos + 1
        args_str = ""

        while pos < len(code) and paren_count > 0:
            if code[pos] == '(':
                paren_count += 1
            elif code[pos] == ')':
                paren_count -= 1
                if paren_count == 0:
                    break
            args_str += code[pos]
            pos += 1

        # Split arguments (simplified - doesn't handle nested calls well)
        if not args_str.strip():
            return []

        # Simple split by comma (won't work perfectly for complex args)
        args = [arg.strip() for arg in args_str.split(',')]
        return args

    def get_function_names(self, code: str) -> Set[str]:
        """
        Quick extraction of just function names.

        Args:
            code: PHP source code

        Returns:
            Set of function names
        """
        functions = self.extract_functions(code)
        return {f.name for f in functions}

    def get_called_functions(self, code: str) -> Set[str]:
        """
        Quick extraction of called function names.

        Args:
            code: PHP source code

        Returns:
            Set of called function names
        """
        calls = self.extract_function_calls(code)
        return {c.name for c in calls}
