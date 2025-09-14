import os
import fnmatch


def get_gitignore_patterns():
    """Reads and parses the .gitignore file, returning a list of patterns."""
    patterns = []
    if os.path.exists('.gitignore'):
        with open('.gitignore', 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Add patterns for both files and directories
                    patterns.append(line)
                    if not line.endswith('/'):
                        patterns.append(line + '/')
    return patterns


def is_ignored(path, gitignore_patterns):
    """Checks if a given path matches any of the .gitignore patterns."""
    for pattern in gitignore_patterns:
        if fnmatch.fnmatch(path, pattern) or any(
                fnmatch.fnmatch(part, pattern.strip('/')) for part in path.split(os.sep)):
            return True
    return False


def find_non_python_files():
    """Finds all non-Python files, excluding ignored files and directories."""
    gitignore_patterns = get_gitignore_patterns()
    non_python_files = []

    always_ignore = ['.git/', '.idea/', '__pycache__/', '*.pyc', '*.pyo', '*.egg-info/', 'dist/', 'build/']
    gitignore_patterns.extend(always_ignore)

    for root, dirs, files in os.walk('.'):
        dirs[:] = [d for d in dirs if not is_ignored(os.path.join(root, d, ''), gitignore_patterns)]

        for filename in files:
            if filename.endswith('.py'):
                continue

            filepath = os.path.join(root, filename)
            if not is_ignored(filepath, gitignore_patterns):
                non_python_files.append(filepath.replace('\\', '/'))

    return non_python_files


if __name__ == "__main__":
    files_to_include = find_non_python_files()
    with open('MANIFEST.in', 'w') as f:
        f.write("# This file is auto-generated. Review before committing.\n")
        f.write("include readme.md\n")
        f.write("include SECURITY.md\n")
        f.write("include CONTRIBUTING.md\n")
        f.write("include LICENSE.txt\n")
        f.write("include coverage.xml\n")
        for filepath in files_to_include:
            if filepath.startswith('./authtuna/'):
                f.write(f"include {filepath[2:]}\n")
    print("\n'MANIFEST.in' has been created/updated successfully.")
