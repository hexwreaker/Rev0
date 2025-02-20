import sys
import lief

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

def main():
    # binary version 1
    binpath_v1 = sys.argv[1]
    binname_v1 = binpath_v1[binpath_v1.rfind('/')+1:]

    # binary version 2
    binpath_v2 = sys.argv[2]
    binname_v2 = binpath_v2[binpath_v2.rfind('/')+1:]

    print(f"diffing the binary versions : {binpath_v1} VS {binpath_v2}")

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
            return -1
    except Exception as e:
        print(f"Error \"{e}\" : lief can't open the files.")
        return -1

    if binary_format == "ELF":
        exports_v1 = lief_get_elf_exported_functions(bin_v1)
        exports_v2 = lief_get_elf_exported_functions(bin_v2)
        print(exports_v1)
        print(exports_v2)

        syms_added = list(set(exports_v2) - set(exports_v1))
        syms_deleted = list(set(exports_v1) - set(exports_v2))

        print(syms_added)
        print(syms_deleted)

    else:
        pass # to do PE and MACH-O
    return 0  

main()





