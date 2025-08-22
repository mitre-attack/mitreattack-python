"""
print_java_imports.py

This Python script generates Java import statements for all packages in a given directory. 
It's useful when you want to import all classes from all packages in a directory.

Usage:
    Run the script from the command line with the directory as an argument:
    python print_java_imports.py <directory_path>
    Replace <directory_path> with the path to the directory for which you want to generate import statements.

Functions:
    createImportStatement(package_path): 
        This function takes a package path as an argument and returns a string that is a Java import statement 
        for all classes in that package.

    print_java_imports(directory): 
        This function walks through the directory structure of the provided directory and prints an import 
        statement for each subdirectory.

Error handling:
    The script checks if the provided argument is a valid directory. If it's not, it prints an error message 
    and exits with a status code of 1.

    If the script is run without exactly one argument, it prints a usage message and exits with a status code of 1.
"""
import os
import sys

def createImportStatement(package_path):
    """
    This function takes a package path as an argument and returns a string that is a Java import statement 
    for all classes in that package.
    """
    return f"import {package_path.replace(os.sep, '.')}.*;"

def getJavaImports(directory, package_name):
    """
    This function walks through the directory structure of the provided directory and returns a list of import 
    statements for each subdirectory.
    """
    import_statements = []
    for root, dirs, files in os.walk(directory):
        
        # Get the relative path from the directory to the current root
        relative_path = os.path.relpath(root, directory)

        if package_name not in relative_path.replace(os.sep,"."):
            #Skip directories that are not part of the package
            continue

        #remove everything before the package name, but keep the package name
        relative_path = relative_path[relative_path.index(package_name.replace(".",os.sep)):]
        
        # Skip the current directory (.)
        if relative_path == ".":
            continue
        
        # Create and add the import statement to the list
        import_statement = createImportStatement(relative_path)
        import_statements.append(import_statement)
    
    return import_statements

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python print_java_imports.py <directory_path>")
        sys.exit(1)
    
    directory_path = sys.argv[1]
    
    if not os.path.isdir(directory_path):
        print(f"The path {directory_path} is not a valid directory.")
        sys.exit(1)
    
    import_statements = getJavaImports(directory_path)
    for statement in import_statements:
        print(statement)