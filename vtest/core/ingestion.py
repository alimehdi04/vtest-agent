import os
from pathlib import Path
import pathspec
from vtest.core.graph import build_dependency_graph

def _get_pathspec(base_path: Path):
    """Loads .gitignore rules and appends absolute fail-safes."""
    lines = [".git/", "node_modules/", "venv/", ".venv/", "__pycache__/", "dist/", ".idea/"]
    gitignore = base_path / ".gitignore"
    if gitignore.exists():
        lines.extend(gitignore.read_text(errors="ignore").splitlines())
    return pathspec.PathSpec.from_lines(pathspec.patterns.GitWildMatchPattern, lines)

def scan_codebase(base_path: str) -> dict:
    """Walks the directory respecting .gitignore to detect language and build the AST graph."""
    path = Path(base_path)
    spec = _get_pathspec(path)
    
    file_extensions = {}
    framework_indicators = {
        "pom.xml": "Spring Boot",
        "next.config.js": "Next.js",
        "package.json": "Node.js",
        "requirements.txt": "Python",
        "Pipfile": "Python"
    }
    
    detected_framework = "Unknown"
    total_files = 0
    source_files = []
    
    for root, dirs, files in os.walk(path):
        # Filter ignored directories in-place (must append '/' for pathspec directory matching)
        dirs[:] = [d for d in dirs if not spec.match_file(os.path.relpath(os.path.join(root, d), path) + "/")]
        
        for file in files:
            rel_path = os.path.relpath(os.path.join(root, file), path)
            if spec.match_file(rel_path):
                continue
                
            total_files += 1
            file_path = Path(root) / file
            ext = file_path.suffix
            
            if ext:
                file_extensions[ext] = file_extensions.get(ext, 0) + 1
            
            # Deep Framework Detection
            if detected_framework == "Unknown":
                if file == "requirements.txt":
                    content = file_path.read_text(errors="ignore").lower()
                    if "fastapi" in content:
                        detected_framework = "FastAPI"
                    elif "flask" in content:
                        detected_framework = "Flask"
                    elif "django" in content:
                        detected_framework = "Django"
                elif file == "package.json":
                    content = file_path.read_text(errors="ignore").lower()
                    if "next" in content:
                        detected_framework = "Next.js"
                    elif "express" in content:
                        detected_framework = "Express"
                
    primary_ext = max(file_extensions, key=file_extensions.get) if file_extensions else ""
    ext_to_lang = {".java": "Java", ".py": "Python", ".ts": "TypeScript", ".tsx": "TypeScript/React", ".js": "JavaScript"}
    primary_lang = ext_to_lang.get(primary_ext, "Unknown")
    
    dependency_graph = build_dependency_graph(source_files)
    
    return {
        "primary_language": primary_lang,
        "framework": detected_framework,
        "total_files": total_files,
        "path": base_path,
        "graph": dependency_graph,
        "source_files": source_files
    }

# import os
# from pathlib import Path
# from vtest.core.graph import build_dependency_graph

# IGNORE_DIRS = {".git", "node_modules", "venv", "__pycache__", ".next", "target", "dist", ".idea"}

# def scan_codebase(base_path: str) -> dict:
#     """
#     Walks the directory to detect the primary language and framework.
#     """
#     path = Path(base_path)
    
#     file_extensions = {}
    
#     # Heuristics to detect specific environments
#     framework_indicators = {
#         "pom.xml": "Spring Boot",
#         "next.config.js": "Next.js",
#         "next.config.mjs": "Next.js",
#         "package.json": "Node.js",
#         "requirements.txt": "Python",
#         "Pipfile": "Python"
#     }
    
#     detected_framework = "Unknown"
#     total_files = 0
    
#     for root, dirs, files in os.walk(path):
#         # Mutate dirs in-place to skip ignored directories entirely
#         dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        
#         for file in files:
#             total_files += 1
#             ext = Path(file).suffix
            
#             if ext:
#                 file_extensions[ext] = file_extensions.get(ext, 0) + 1
            
#             # Fast framework detection based on root configuration files
#             if file in framework_indicators and detected_framework == "Unknown":
#                 detected_framework = framework_indicators[file]
                
#     # Determine primary language by the most common file extension
#     primary_ext = max(file_extensions, key=file_extensions.get) if file_extensions else ""
    
#     ext_to_lang = {
#         ".java": "Java", 
#         ".py": "Python", 
#         ".ts": "TypeScript", 
#         ".tsx": "TypeScript/React", 
#         ".js": "JavaScript"
#     }
    
#     primary_lang = ext_to_lang.get(primary_ext, "Unknown")
    
#     # return {
#     #     "primary_language": primary_lang,
#     #     "framework": detected_framework,
#     #     "total_files": total_files,
#     #     "path": base_path
#     # }

#     # Gather Path objects for the graph builder
#     source_files = [
#         Path(root) / file 
#         for root, dirs, files in os.walk(path) 
#         for file in files if file.endswith('.py')
#     ]
    
#     dependency_graph = build_dependency_graph(source_files)
    
#     return {
#         "primary_language": primary_lang,
#         "framework": detected_framework,
#         "total_files": total_files,
#         "path": base_path,
#         "graph": dependency_graph, # <-- The LLM can now query this
#         "source_files": source_files
#     }