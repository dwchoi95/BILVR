import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from tree_sitter import Language, Parser
import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp


class FunctionParser:
    def __init__(self, language:str="c"):
        language = language.lower()
        if language == "c":
            lang = tsc.language()
        elif language == "cpp" or language == "c++":
            lang = tscpp.language()
        else:
            raise ValueError(f"Unsupported language: {language}")
        
        self.lang = Language(lang)
        self.parser = Parser(self.lang)
    
    def parse(self, b_code:bytes):
        return self.parser.parse(b_code)
        
    
    def _iter_nodes_by_type(self, node, node_type):
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type == node_type:
                yield current
            stack.extend(reversed(current.children))

    def _extract_function_name(self, function_node):
        declarator = function_node.child_by_field_name("declarator")
        if declarator is None:
            return None

        identifier_node = self._find_identifier_in_declarator(declarator)
        if identifier_node is None:
            return None

        return identifier_node.text.decode("utf-8")

    def _find_identifier_in_declarator(self, node):
        if node.type in {"identifier", "field_identifier"}:
            return node

        nested = node.child_by_field_name("declarator")
        if nested is not None:
            result = self._find_identifier_in_declarator(nested)
            if result is not None:
                return result

        for child in node.children:
            if child.type == "parameter_list":
                continue
            result = self._find_identifier_in_declarator(child)
            if result is not None:
                return result

        return None

    def run(self, c_code:str, func_name:str) -> str:
        source_bytes = bytes(c_code, "utf-8")
        tree = self.parse(source_bytes)

        targets = {func_name}
        if "::" in func_name:
            targets.add(func_name.split("::")[-1])

        for node in self._iter_nodes_by_type(tree.root_node, "function_definition"):
            name = self._extract_function_name(node)
            if name in targets:
                declarator = node.child_by_field_name("declarator")
                if declarator is None:
                    return source_bytes[node.start_byte:node.end_byte].decode("utf-8").lstrip()

                prefix = source_bytes[node.start_byte:declarator.start_byte].decode("utf-8")
                function_tail = source_bytes[declarator.start_byte:node.end_byte].decode("utf-8").lstrip()
                if prefix:
                    return f"{prefix} {function_tail}"
                return function_tail

        return None
