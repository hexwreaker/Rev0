import sys
import os
import subprocess
import lief
from capstone import *

lief.logging.set_level(lief.logging.LEVEL.ERROR)

def diff_filesystems(old_dir, new_dir):
    # Define out arrays
    old_files = []
    new_files = []
    diff_files = []

    # Run the diff command for the 'Only in OLD' case and process the output
    diff_cmd = ["diff", "-qr", old_dir, new_dir]
    diff_output = subprocess.run(diff_cmd, capture_output=True, text=True)
    for line in diff_output.stdout.splitlines():
        if f"Only in {old_dir}" in line:
            processed_line = line.replace(": ", "/")[len(old_dir)+8:]
            if processed_line[0] == '/':
                processed_line = processed_line[1:]
            old_files.append(processed_line)

    # Run the diff command for the 'Only in NEW' case and process the output
    for line in diff_output.stdout.splitlines():
        if f"Only in {new_dir}" in line:
            processed_line = line.replace(": ", "/")[len(new_dir)+8:]
            if processed_line[0] == '/':
                processed_line = processed_line[1:]
            new_files.append(processed_line)

    # Run the diff command for the files that differ
    for line in diff_output.stdout.splitlines():
        if "Files" in line and "differ" in line and "No such" not in line:
            file1 = line[6+len(old_dir):].split(" and ")[0]
            if file1[0] == '/':
                file1 = file1[1:]
            diff_files.append(file1)

    return old_files, new_files, diff_files

def lief_get_elf_exported_functions(elf):
    dyn = elf.dynamic_symbols
    exps = {}
    for exp in dyn:
        if exp.size != 0 and exp.type == lief.ELF.Symbol.TYPE.FUNC:
            exps[exp.name] = exp
    return exps

def lief_get_elf_imported_functions(elf):
    dyn = elf.dynamic_symbols
    imps = {}
    for imp in dyn:
        if imp.size == 0 and imp.type == lief.ELF.Symbol.TYPE.FUNC:
            imps[imp.name] = imp
    return imps

def diff_exports(binpath_v1, binpath_v2):
    # Load the file using lief
    bin_v1 = None
    bin_v2 = None
    binary_format = None
    try:
        bin_v1 = lief.parse(binpath_v1)
        bin_v2 = lief.parse(binpath_v2)
        # Check the file type
        if isinstance(bin_v1, lief.ELF.Binary) and isinstance(bin_v2, lief.ELF.Binary):
            binary_format = "ELF"
        elif isinstance(bin_v1, lief.PE.Binary) and isinstance(bin_v2, lief.PE.Binary):
            binary_format = "PE"
        elif isinstance(bin_v1, lief.MachO.Binary and isinstance(bin_v2, lief.MachO.Binary)):
            binary_format = "MACH-O"
        else:
            printf("Error : the binaries are not of the same format (elf, pe, macho) or they are not assembly objects (exe, obj, dll).")
            return None, None
    except Exception as e:
        print(f"Error \"{e}\" : lief can't open the files.")
        return None, None

    funcs_added = []
    funcs_deleted = []
    if binary_format == "ELF":
        exports_v1 = lief_get_elf_exported_functions(bin_v1)
        exports_v2 = lief_get_elf_exported_functions(bin_v2)
        funcs_added = [{exp: exports_v2[exp]} for exp in list(set(exports_v2) - set(exports_v1))]
        funcs_deleted = [{exp: exports_v1[exp]} for exp in list(set(exports_v1) - set(exports_v2))]
    else:
        printf("Error : PE and MachO binary formats are not yet supported.")
        return None, None # to do PE and MACH-O
    return funcs_added, funcs_deleted

def diff_instructions(binpath_v1, binpath_v2):
    from bindiff import BinDiff

    diff = BinDiff.from_binary_files(binpath_v1, binpath_v2, "out.BinDiff")
    print(diff.similarity, diff.confidence)

if __name__ == "__main__":
    # Ensure correct number of arguments
    if len(sys.argv) != 3:
        print("Usage : {} <old_directory> <new_directory>".format(sys.argv[0]))
        sys.exit(1)
    
    # Get the directories from the command line arguments
    old_fs = sys.argv[1]
    new_fs = sys.argv[2]

    diff_instructions(old_fs, new_fs)
    exit()

    # diffing filesystems
    old_files, new_files, diff_files = diff_filesystems(old_fs, new_fs)

    # diffing symbols between binary versions
    for file in diff_files:
        funcs_added, funcs_deleted = diff_exports(old_fs+"/"+file, new_fs+"/"+file)
        print(file)
        if funcs_added == None or funcs_deleted == None:
            print(f"Error : during binary versions diffing of {file}.")
        print(f"funcs_added : {funcs_added}")
        print(f"funcs_deleted : {funcs_deleted}")
