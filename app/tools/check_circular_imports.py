import os
import ast
import sys

def get_imports(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        tree = ast.parse(f.read())
    
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                imports.append(n.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
    return imports

def check_cycles(app_path):
    graph = {}
    for root, _, files in os.walk(app_path):
        for file in files:
            if file.endswith('.py'):
                full_path = os.path.join(root, file)
                module_name = os.path.relpath(full_path, os.path.dirname(app_path)).replace(os.path.sep, '.').replace('.py', '')
                if module_name.endswith('.__init__'):
                    module_name = module_name[:-9]
                try:
                    graph[module_name] = [imp for imp in get_imports(full_path) if imp.startswith('app.')]
                except Exception as e:
                    print(f"Error parsing {full_path}: {e}")

    def find_cycle(v, visited, rec_stack, path):
        visited.add(v)
        rec_stack.add(v)
        path.append(v)
        
        for neighbor in graph.get(v, []):
            if neighbor not in visited:
                if find_cycle(neighbor, visited, rec_stack, path):
                    return True
            elif neighbor in rec_stack:
                path.append(neighbor)
                return True
        
        rec_stack.remove(v)
        path.pop()
        return False

    visited = set()
    for node in graph:
        if node not in visited:
            path = []
            if find_cycle(node, visited, set(), path):
                print(f"Found Circular Import Cycle: {' -> '.join(path)}")
                return True
    
    print("No Circular Imports Detected in app/ paths.")
    return False

if __name__ == "__main__":
    check_cycles(os.path.join(os.getcwd(), 'app'))
