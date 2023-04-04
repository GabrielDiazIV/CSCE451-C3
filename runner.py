# USAGE: python runner.py [function_name] ..argv
# script that creates runnable file for whatever is selected

# 1. Create a main file [function_name]-main.c, with main method that only includes & calls [function_name]
# 2. Populate arguments values
# 3. gcc [function_name]-main.c -o [function_name]-main.o
# 4. ./[function_name]-main.o

import sys
import logging
import os
import subprocess

## doesn't do nothing nowS
import ghidra_bridge

# Load Ghidra Bridge and make Ghidra namespace available
TIMEOUT = 1000
gb = ghidra_bridge.GhidraBridge(namespace=globals(), response_timeout=TIMEOUT)

MAIN_TEMPLATE = '''#include <iostream>
#include "{file_name}.h"

int main() {{
    std::cout << {function_name}({args}) << std::endl;
    return 0;
}} 
'''

def get_program_info():
    """Gather information for currentProgram in Ghidra."""
    logging.debug("Gathering program information...")
    program_info = {}
    program_info["program_name"] = currentProgram.getName()
    program_info["creation_date"] = gb.remote_eval("currentProgram.getCreationDate()")
    program_info["language_id"] = gb.remote_eval("currentProgram.getLanguageID()")
    program_info["compiler_spec_id"] = gb.remote_eval("currentProgram.getCompilerSpec().getCompilerSpecID()")
    
    return program_info

def runner(executable_path):

    # Run the GCC command using subprocess
    print(f"--- EXECUTING {executable_path} ---")
    try:
        output = subprocess.check_output(executable_path, stderr=subprocess.STDOUT)
        print(output.decode())
    except subprocess.CalledProcessError as e:
        print(f"--- EXECUTING FAILED ---")
        print("Compilation failed:", e.output.decode())
        exit(1)

def create_main(filename, args):
    print(f"--- CREATING MAIN {filename} ---")

    program_info = get_program_info()
    output_dir = os.path.join("examples", program_info["program_name"] + "_extraction")
    
    try:
        main_filename = f"{filename}-main.c"
        path = os.path.join(output_dir, main_filename)
        function_name = filename.split("@")[0]
        with open(path, "w") as f:
            f.write(MAIN_TEMPLATE.format(file_name = filename, function_name=function_name, args=','.join(args)))
        return path
    except Exception as e:
        print(f"--- CREATING MAIN FAILED ---")
        print(e)
        exit(1)
    

def compile(main_file):
    print(f"--- COMPILING {main_file} ---")
    # Define the GCC command to run
    output_name = main_file.split('.c')[0]+".o"
    gcc_command = ["g++", main_file, "-o", output_name]

    # Run the GCC command using subprocess
    try:
        output = subprocess.check_output(gcc_command, stderr=subprocess.STDOUT)
        if len(output.decode()) != 0:
            print(output.decode())
    except subprocess.CalledProcessError as e:
        print(f"--- COMPILING FAILED ---")
        print("Compilation failed:", e.output.decode())
        exit(1)

    return output_name
    

# filename arg must come in the format {function.name}@{function.getEntryPoint()}
def main(): 
    if len(sys.argv) < 2:
        print("No filename passed")
        return 1
        
    main_file =  create_main(sys.argv[1], sys.argv[2:])
    executable_path = compile(main_file)
    runner(executable_path)

if __name__ == '__main__':
    main()


