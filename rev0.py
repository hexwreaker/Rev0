#!/bin/python3
import os
import sys
import magic
import argparse
import webbrowser
from diff_bin import binary_to_binexport
from diff_bin import binaries_diff
from diff_filesys import diff_filesys
from maproject import sym_map
from collections import defaultdict
from bindiff_to_html import process_bindiff_files

RED = '\033[31m'
GREEN = '\033[32m'
BLUE = '\033[34m'
NOC = '\033[0m'

IDA_PATH = "/home/matthias/idapro-8.3/"

def symap(fs_dir, out):
    if out == None:
        out = "rev0-symap.html"
    last_slash = fs_dir.rfind('/')
    fs_dir_name = fs_dir
    if last_slash >= 0:
        fs_dir_name = fs_dir[last_slash+1:]
    print(f"[i] Rev0 symap: {fs_dir}")
    # Assert that it's a valid directory
    if not os.path.isdir(fs_dir):
        print(f"Error : {fs_dir} is not a valid directory.")
        exit(-1)
    # Calling the graph function
    print(f'[i] Graph generated in : ', end='')
    sym_map(fs_dir, out)

def symap_args(args):
    fs_dir = args.FILESYS
    # Default out file path
    if hasattr(args, 'out'):
        out = args.out
    else:
        out = "rev0-symap.html"
    symap(fs_dir, out)

def diff_fs(fs_dir1, fs_dir2, format, output, output_deleted, output_added, output_changed):
    print(f"[i] Rev0 diff:\t  {fs_dir1}  VS  {fs_dir2}")
    # diffing filesystems
    old_files, new_files, diff_files = diff_filesys(fs_dir1, fs_dir2)

    # No colored write if file is specified
    if output != None or output_deleted != None or output_added != None or output_changed != None:
        RED = ""
        GREEN = ""
        BLUE = ""
        NOC = ""
    else:
        RED = '\033[31m'
        GREEN = '\033[32m'
        BLUE = '\033[34m'
        NOC = '\033[0m'

    # Print the output by format :
    out = ""
    out_deleted = ""
    out_added = ""
    out_changed = ""
    if format == 'cmb':
        changes = defaultdict(list)
        for file in old_files:
            out_deleted += f"{RED}- {file}{NOC}\n"
            changes[file.rsplit("/", 1)[0]].append(f"{RED}- {file}{NOC}\n")
        for file in new_files:
            out_added += f"{GREEN}+ {file}{NOC}\n"
            changes[file.rsplit("/", 1)[0]].append(f"{GREEN}+ {file}{NOC}\n")
        for file in diff_files:
            out_changed += f"{BLUE}~ {file}{NOC}\n"
            changes[file.rsplit("/", 1)[0]].append(f"{BLUE}~ {file}{NOC}\n")
        for directory in sorted(changes):
            for entry in sorted(changes[directory]):
                out += entry
    elif format == 'sep':
        # Print old files
        out += f"Files deleted in new version :\n"
        for file in old_files:
            out_deleted += f"{file}\n"
            out += f"{RED}- {file}{NOC}\n"
        out += f"Files added in new version :\n"
        for file in new_files:
            out_added += f"{file}\n"
            out += f"{GREEN}+ {file}{NOC}\n"
        out += f"Files modified in new version :\n"
        for file in diff_files:
            out_changed += f"{file}\n"
            out += f"{BLUE}~ {file}{NOC}\n"
    # Write to output or print to stdout :
    if output != None:
        try :
            outfile = open(output, 'w')
            outfile.write(out)
            print(f"[i] output write into {GREEN}\"{output}\"{NOC}")
        except Exception as e:
            print(f"[!] Error : {e}")
    # Write to -oa, -od or -oc
    if output_deleted != None:
        try :
            outfile = open(output_deleted, 'w')
            outfile.write(out_deleted)
            print(f"[i] deleted files write into {GREEN}\"{output_deleted}\"{NOC}")
        except Exception as e:
            print(f"[!] Error : {e}")
    if output_added != None:
        try :
            outfile = open(output_added, 'w')
            outfile.write(out_added)
            print(f"[i] added files write into {GREEN}\"{output_added}\"{NOC}")
        except Exception as e:
            print(f"[!] Error : {e}")
    if output_changed != None:
        try :
            outfile = open(output_changed, 'w')
            outfile.write(out_changed)
            print(f"[i] changed files write into {GREEN}\"{output_changed}\"{NOC}")
        except Exception as e:
            print(f"[!] Error : {e}")
    if output == None and output_deleted == None and output_added == None and output_changed == None:
        print(out)

def diff_fs_args(args):
    diff_fs(args.FILESYS1, args.FILESYS2, args.format, args.output, args.output_deleted, args.output_added, args.output_changed)

def is_assembly_file(filepath):
    return os.path.exists(filepath) and ("BinExport" not in filepath) and any(x in magic.from_file(filepath).lower() for x in ["elf", "pe32", "pe64", "pe32+", "mach-o"])        

def bindiff(fs_dir1, fs_dir2, outdir, excludes, silktouch, ida_path, verbose, timeout):
    _, _, diff_files = diff_filesys(fs_dir1, fs_dir2)

    # sanitize excludes
    fullpath_fs_dir1 = os.path.abspath(fs_dir1)
    if fullpath_fs_dir1[-1] != '/':
        fullpath_fs_dir1 += "/"
    excludes = [os.path.abspath(x)[len(fullpath_fs_dir1):] for x in excludes]

    # bindiff files
    count = 0
    for file in diff_files:
        out_dir = outdir+"/"
        # Verify it's an assembly file
        bin_1 = fs_dir1+"/"+file
        bin_2 = fs_dir2+"/"+file
        last_slash = file.rfind("/")
        filename = file
        if last_slash >= 0:
            out_dir += file[:last_slash+1]
            filename = file[last_slash+1:]
        dst_filepath = out_dir+filename+"_vs_"+filename+".results"
        if file not in excludes and (not silktouch or not os.path.exists(dst_filepath)) and (is_assembly_file(bin_1) and is_assembly_file(bin_2)):
            # Export binaries into BinExport format
            binex_1 = binary_to_binexport(ida_path, bin_1, verbose, timeout)
            binex_2 = binary_to_binexport(ida_path, bin_2, verbose, timeout)
            # Bindiff
            # if out_dir doesn't exist, create it.
            os.makedirs(out_dir, exist_ok=True)
            # Check if previous export succeed
            if os.path.exists(binex_1) and os.path.exists(binex_2):
                binaries_diff(binex_1, binex_2, out_dir, verbose, timeout)
                count += 1
                print(f"{GREEN}[{count}/{len(diff_files)}] {file} done !{NOC}")
            else:
                count += 1
                print(f"{RED}[{count}/{len(diff_files)}] {file} FAILED !{NOC}")
            # remove BinExport files
            try:
                os.remove(binex_1)
                os.remove(binex_2)
            except Exception as e:
                pass
        else:
            count += 1
            print(f"{BLUE}[{count}/{len(diff_files)}] {file} skip.{NOC}")

def bindiff_args(args):
    bindiff(args.FILESYS1, args.FILESYS2, outdir, args.excludes, args.silktouch, args.ida_path, args.verbose, args.timeout)

def readiff(args):
    file = args.BINDIFF_FILE
    out = args.outfile
    res = process_bindiff_files(file, out)
    webbrowser.open("file://"+os.path.abspath(res))
    


if __name__ == '__main__':
    description = """\
    The Rev0 project to help you reversing entire filesystems.
    By @hexwreaker on github : https://github.com/hexwreaker."""
    argp = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)
    argp.add_argument("-v", "--verbose", help="set the output in verbose mode, print more informations", action='store_true')

    # Create subparsers
    subparsers = argp.add_subparsers(dest="command", required=True, help="Available actions")

    # Action 1: symap -fs FILESYSTEM
    #   map the symbols in a filesystem
    parser_1 = subparsers.add_parser("symap", help="map the symbols used between binaries/libraries in the filesystem path FS_PATH.")
    parser_1.add_argument("-o", "--out", dest="out", metavar="FILEPATH", default="rev0-symap.html", help="specify a filepath to write the graph to. By default it's \"symap.html\" in PWD")
    parser_1.add_argument("FILESYS", help="set the filesystem root directory.")
    parser_1.set_defaults(func=symap_args)

    # Action 2: diff -fs FILESYSTEM FILESYSTEM
    #   diffing two versions of filesystem
    parser_2 = subparsers.add_parser("diff", help="diffing the primary and secondary filesystems.")
    parser_2.add_argument("-f", "--format", dest="format", choices=['sep', 'cmb'], default='cmb', help="set the output format. It can be : 'sep' for separated by diff state; 'cmb' for combined in tree directories;")
    parser_2.add_argument("-o", "--output", dest="output", help="set the output file to write to.")
    parser_2.add_argument("-od", "--output-deleted", dest="output_deleted", help="set the output file to write deleted files to.")
    parser_2.add_argument("-oa", "--output-added", dest="output_added", help="set the output file to write added files to.")
    parser_2.add_argument("-oc", "--output-changed", dest="output_changed", help="set the output file to write changed files to.")
    parser_2.add_argument("FILESYS1", help="set the primary filesystem root directory.")
    parser_2.add_argument("FILESYS2", help="set the secondary filesystem root directory.")
    parser_2.set_defaults(func=diff_fs_args)

    # Action 3: bindiff
    #   diffing all the binaries using bindiff from zynamics
    parser_3 = subparsers.add_parser("bindiff", help="diffing common binaries between primary and secondary filesystems. The bindiff results are stored in a filesystem copy, located in the Rev0 project directory. It use the bindiff tool by \"Zynamics\", the python-binexport tool by \"Quarkslab\" and need Ida pro beeing installed.")
    parser_3.add_argument("-o", "--out", dest="outdir", metavar="DIRECTORY", default="./rev0-bindiff", help="specify the directory where the bindiff's results will be writed. A copy of the filesystem will be created in, containing the bindiff data of the binaries. By default it's located in \"./rev0-bindiff/\" in PWD")
    parser_3.add_argument("-i", "--ida-path", dest="ida_path", metavar="IDA_PATH", default=IDA_PATH, help="specify the directory of the user's Ida pro. By default the IDA_PATH hardcoded variable in the python script will be used.")
    parser_3.add_argument("-v", "--verbose", type=int, choices=[0, 1, 2, 3], default=0, help="set verbosity level (0=minimum, 1=low, 2=medium, 3=high)")
    parser_3.add_argument("-s", "--silktouch", action="store_true", dest="silktouch", help="don't bindiff if a result already exist in out directory.")
    parser_3.add_argument("-t", "--timeout", dest="timeout", type=int, default=6, help="set the timeout value in seconds, for skipping if a subprocess command is too long. By default timeout=6.")
    parser_3.add_argument("-x", "--exclude", dest="excludes", nargs='+', default=[], help="specify files to be skipped. ATTENTION, you should only indicate path pointing to primary filesystem binaries, it will automatically skip them.")
    parser_3.add_argument("FILESYS1", help="set the primary filesystem root directory.")
    parser_3.add_argument("FILESYS2", help="set the secondary filesystem root directory.")
    parser_3.set_defaults(func=bindiff_args)
    
    # Action 4: readiff 
    #   read the bindiff results of a file or a full directory.
    parser_4 = subparsers.add_parser("readiff", help="Read the bindiff results. Can lookup for a unique file or a full directory.")
    parser_4.add_argument("-o", "--out", dest="outfile", metavar="FILEPATH", default="./bindiff_results.html", help="specify the filename of the HTML file to write. By default it's \"./bindiff_results.html\" in PWD.")
    parser_4.add_argument("BINDIFF_FILE", type=str, help="the path of the target \"bindiff results\" to read.")
    parser_4.set_defaults(func=readiff)
    
    # Parse arguments
    args = argp.parse_args()
    # Call the corresponding function
    args.func(args)
    





