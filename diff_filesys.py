import sys
import os
import subprocess
import lief
from capstone import *

lief.logging.set_level(lief.logging.LEVEL.ERROR)

def diff_filesys(old_dir, new_dir):
    """Diffing two filesystem. It use the diff GNU command.
    :param old_dir: the primary filesystem dir path
    :type old_dir: str
    :param new_dir: the secondary filesystem dir path
    :type new_dir: str
    :returns: arrays of old, new and changed binaries.
    :rtype: (list, list, list)
    """
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

if __name__ == "__main__":
    # Ensure correct number of arguments
    if len(sys.argv) != 3:
        print("Usage : {} <old_directory> <new_directory>".format(sys.argv[0]))
        sys.exit(1)
    
    # Get the directories from the command line arguments
    old_fs = sys.argv[1]
    new_fs = sys.argv[2]

    # diffing filesystems
    old_files, new_files, diff_files = diff_filesys(old_fs, new_fs)
    exit()
    # diffing symbols between binary versions
    for file in diff_files:
        funcs_added, funcs_deleted = diff_exports(old_fs+"/"+file, new_fs+"/"+file)
        print(file)
        if funcs_added == None or funcs_deleted == None:
            print(f"Error : during binary versions diffing of {file}.")
        print(f"funcs_added : {funcs_added}")
        print(f"funcs_deleted : {funcs_deleted}")
