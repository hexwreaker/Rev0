import sys
import lief
import subprocess
import os

RED = '\033[31m'
GREEN = '\033[32m'
BLUE = '\033[34m'
NOC = '\033[0m'

def lief_get_elf_exported_functions(elf):
    """Use lief to get the exported functions from an ELF.
    :param elf: the lief parsed ELF.
    :type elf: lief.parse.ELF
    :returns: array of the binary exported functions.
    :rtype: list
    """
    dyn = elf.dynamic_symbols
    exps = {}
    for exp in dyn:
        if exp.size != 0 and exp.type == lief.ELF.Symbol.TYPE.FUNC:
            exps[exp.name] = exp
    return exps

def lief_get_elf_imported_functions(elf):
    """Use lief to get the imported functions from an ELF.
    :param elf: the lief parsed ELF.
    :type elf: lief.parse.ELF
    :returns: array of the binary imported functions.
    :rtype: list
    """
    dyn = elf.dynamic_symbols
    imps = {}
    for imp in dyn:
        if imp.size == 0 and imp.type == lief.ELF.Symbol.TYPE.FUNC:
            imps[imp.name] = imp
    return imps

def diff_exported_funcs(binpath_v1, binpath_v2):
    """Diff two binary and return the functions that are added in v2 and deleted in v2.
    :param binpath_v1: the primary binary.
    :type binpath_v1: str
    :param binpath_v2: the secondary binary.
    :type binpath_v2: str
    :returns: two arrays of funcs that are added, deleted in secondary binary. 
    :rtype: (list, list)
    """
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


def disas_ida(ida_path, binpath):
    """Disassemble a binary using ida batch mode and return the ida db created file.
    :param ida_path: the ida binary path on the user system.
    :type ida_path: str
    :param binpath: the binary to disassemble.
    :type binpath: str
    :returns: the ida db created file path.
    :rtype: str
    """
    # removing potentialy existing crash dump to avoid the display of the Ida warning crash window.
    subprocess.run(["rm", "/tmp/ida/*.dmp"], check=True)
    # disas using ida
    print(f"Disassembling {binpath}...", end='')
    res = subprocess.run([ida_path, "-A", "-B", binpath], check=True, capture_output=True, text=True)
    print(res.stderr)
    print(f"[ok]")
    return binpath+'.i64'


def binary_to_binexport(ida_path, binpath, verbose, timeout):
    """Using the quarkslab binexporter (python-binexport) tool, this function export a binary file into BinExport (google protobuf) file format. This is necessary to process it with bindiff then.
    :param ida_path: the ida binary path on the user system.
    :type ida_path: str
    :param binpath: the binary to disassemble.
    :type binpath: str
    :returns: the ida db created file path.
    :rtype: str
    """
    # get fullpath
    if binpath[0] == '/':
        fullpath = binpath
    else:
        fullpath = os.getcwd()+"/"+binpath
    if verbose >= 1:
        print(f"Export {binpath} to BinExport file format")
    try:
        res = subprocess.run(["binexporter", "-i", ida_path, fullpath], check=True, capture_output=True, text=True, timeout=timeout)
        if verbose >= 2:
            print(res.stderr)
        if verbose >= 3:
            print(res.stdout)
    except Exception as e:
        if verbose >= 2:
            print(e)
        
    return fullpath+'.BinExport'

def binaries_diff(binpath_v1, binpath_v2, out_dir, verbose, timeout):
    """Using zynamics's bindiff tool to diff two binaries from their BinExport files.
    :param binpath_v1: the primary binary path
    :type binpath_v1: str
    :param binpath_v2: the secondary binary path.
    :type binpath_v2: str
    :returns: the ida db created file path.
    :rtype: str
    """
    if verbose >= 1:
        print(f"{BLUE}Diffing{NOC} : {binpath_v1} vs {binpath_v2} to {out_dir}")
    try:
        res = subprocess.run(["bindiff", binpath_v1, binpath_v2, "--output_dir", out_dir,"--output_format", "log"], check=True, capture_output=True, text=True, timeout=timeout)
        if verbose >= 2:
            print(res.stderr)
        if verbose >= 3:
            print(res.stdout)
    except Exception as e:
        if verbose >= 2:
            print(e)
    return out_dir


if __name__ == "__main__":
    # binary version 1
    binpath_v1 = sys.argv[1]
    binname_v1 = binpath_v1[binpath_v1.rfind('/')+1:]

    # binary version 2
    binpath_v2 = sys.argv[2]
    binname_v2 = binpath_v2[binpath_v2.rfind('/')+1:]

    print(f"diffing the binary versions : {binpath_v1} VS {binpath_v2}")

    diff_exported_funcs(binpath_v1, binpath_v2)


