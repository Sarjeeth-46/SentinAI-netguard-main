import os
import ast
import re

def extract_python_functions(filepath):
    funcs = []
    with open(filepath, 'r', encoding='utf-8') as f:
        try:
            tree = ast.parse(f.read(), filename=filepath)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    funcs.append(node.name)
        except Exception:
            pass
    return funcs

def extract_js_functions(filepath):
    funcs = []
    # Match: function foo(), const foo = (), const foo = async () =>, class methods, etc.
    func_pattern = re.compile(r'(?:function\s+([A-Za-z0-9_]+)\s*\()|(?:const\s+([A-Za-z0-9_]+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z0-9_]+)\s*=>)')
    with open(filepath, 'r', encoding='utf-8') as f:
        try:
            content = f.read()
            for match in func_pattern.finditer(content):
                name = match.group(1) or match.group(2)
                if name:
                    funcs.append(name)
        except Exception:
            pass
    return funcs

if __name__ == "__main__":
    results = {}
    base_dir = r'c:\SentinAI-netguard'
    for root, dirs, files in os.walk(base_dir):
        if any(ignored in root for ignored in ['node_modules', '.git', 'venv', '__pycache__', 'dist', 'build']):
            continue
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, base_dir)
            if file.endswith('.py'):
                f_list = extract_python_functions(full_path)
                if f_list:
                    results[rel_path] = f_list
            elif file.endswith('.js') or file.endswith('.jsx'):
                f_list = extract_js_functions(full_path)
                if f_list:
                    results[rel_path] = f_list

    for filepath in sorted(results.keys()):
        print(f"\n[{filepath}]:")
        for f in sorted(list(set(results[filepath]))):
            print(f"  - {f}")
