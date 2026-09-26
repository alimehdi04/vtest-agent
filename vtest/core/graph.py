import ast
import networkx as nx
from pathlib import Path

def build_dependency_graph(files: list[Path]) -> nx.DiGraph:
    """
    Parses AST to build a directed graph of local file dependencies.
    If A.py imports B.py, the edge is A.py -> B.py.
    """
    graph = nx.DiGraph()
    
    # Map module names (e.g., 'ingestion') to their exact filenames ('ingestion.py')
    module_map = {f.stem: f.name for f in files}
    
    for f in files:
        graph.add_node(f.name)
        
        try:
            tree = ast.parse(f.read_text(errors="ignore"))
            for node in ast.walk(tree):
                # Handle: import module
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        # Only map local files, ignore standard library/pip packages
                        if alias.name in module_map:
                            graph.add_edge(f.name, module_map[alias.name])
                            
                # Handle: from module import function
                elif isinstance(node, ast.ImportFrom):
                    if node.module and node.module in module_map:
                        graph.add_edge(f.name, module_map[node.module])
                        
        except SyntaxError:
            # Skip files with invalid syntax to prevent ingestion crashes
            continue
            
    return graph

def get_taint_chain(graph: nx.DiGraph, target_file: str, depth: int = 2) -> list[str]:
    """
    Calculates the 'blast radius' of a failing file.
    Finds all upstream files that import the target_file.
    """
    if target_file not in graph:
        return [target_file]
        
    affected = {target_file}
    current_level = {target_file}
    
    for _ in range(depth):
        next_level = set()
        for node in current_level:
            try:
                # Predecessors are files that point TO our target file (they import it)
                next_level.update(graph.predecessors(node))
            except nx.NetworkXError:
                pass
        affected.update(next_level)
        current_level = next_level
        
    return list(affected)