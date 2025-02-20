# Map the project binaries and libraries
# create a graph object G = (V, E) où V est un ensemble de sommets et E = (u, v) un ensemble de couples de sommets représentant un arc
#   
# Un sommet V représente un fichier (ELF, librairie) et est composé d'un ensemble de symboles Sv.
# Une arrête E = (u, v) représente un arc entre deux fonctions, c-à-d un symbole utilisé par u dont l'origine est v.
#
# En pratique : G = (V, E) est un graphe où : 
#   - V est un dictionnaire de fichiers : 
#           V = { "#hash_file": fichier }                       // Le dico a pour clef le chemin complet d'un fichier.
#
#       - Un fichier est un dictionnaire : 
#           fichier = { "filename": string,                     // le hash SHA256 du fichier
#                       "file_type": string,                    // le type de fichier : ELF, PE ou Mach-O
#                       "file_subtype": string,                 // le sous-type : Exe, Lib, Reloc, Core, OS ou Proc
#                       "imported_funcs": { "symbol_address": symbol } // la clef est l'adresse à laquelle se trouve le symbole dans le fichier
#                     }
#   
#       - Un sommet (node) correspond à l'utilisation d'un symbole à une adresse dans le fichier :
#           symbol = {  "symbol_name": string,                  // le nom du symbole
#                       "symbol_use": "import|export|call",     // comment est utilisé le symbole dans le programme
#                       "call_in_function": string              // le nom de la fonction dans laquelle est utilisé le symbole, dans le cas d'un call.
#                    }
#   
#   - E est une liste d'arcs orientés (link)
#           E = [arc_1, arc_2]
#               
#       - Un arc orienté correspond à un couple de sommets (import/call, export) :
#           arc = (f"{hash_file}:{import_call_sym_address}", f"{hash_file}:{export_sym_address}")
#           
#
#
#
#   - noeud : "fichier:symbole"
#
#
#
#
#
#   file = {    "filename": string,
#               "filepath": string,
#               "real_filepath": string,
#               "filehash": sha256,
#               "magic_filetype": string,
#               "imports": {},
#               "exports": {},
#          }
#
#
#
#
import lief
import sys
from capstone import *
from capstone.arm import *
import os
import magic
import hashlib
from graph import to_graph_app

lief.logging.set_level(lief.logging.LEVEL.ERROR)

def get_file_type(root, file_path):
    if os.path.islink(file_path):
        return get_file_type(root, os.readlink(file_path))
    elif os.path.isfile(file_path):
        try:
            return magic.Magic(mime=True).from_file(file_path)
        except:
            return f"error : detecting file type of \"{file_path}\"."
    else:
        if file_path[0] == '/':
            if not os.path.exists(file_path):
                return f"error : the file \"{file_path}\" doesn't exist."
            # error : get file type of an absolute file path, maybe a symlink that points out of the project directory
            # trying to find this file from the project root
            return get_file_type(root, root+file_path)
        elif '/' not in file_path:
            return get_file_type(root, root + "/" + file_path)
        else:
            return f"error : unknow file \"{file_path}\""

def list_files(directory):
    res = []
    for root, directories, files in os.walk(directory):
        for file in files:
            if root[-1] != '/': root += "/"
            res.append(root+file)
            
    return res

# pars symlinlks
# def list_files(directory):
#     res = []
#     for root, directories, files in os.walk(directory):
#         for file in files:
#             if root[-1] != '/': root += "/"
#             filepath = root+file
#             if os.path.islink(filepath): # symlink
#                 symtarget = os.readlink(filepath)
#                 if symtarget[0] == '/': # target is absolute from directory
#                     symtarget = directory+symtarget[1:]
#                     if os.path.exists(symtarget):
#                         res.append(symtarget)
#                 else: # target is relative to current directory
#                     res.append(root+symtarget)
#             else : # regular file
#                 res.append(filepath)
#     return res

def sha256sum_file(filepath):
    with open(filepath, 'rb', buffering=0) as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()
    return None

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

def lief_gen_file(directory, filepath):
    real_filepath = filepath
    # Detect if filepath is a regular file or a symlink
    if os.path.islink(filepath): # symlink
        real_filepath = os.readlink(filepath)
        if real_filepath[0] == '/': # absolute path
            real_filepath = directory+real_filepath[1:]
            if not os.path.exists(real_filepath):
                real_filepath = filepath
        else: # relative path
            real_filepath = filepath[:filepath.rfind('/')+1]+real_filepath
    

    # Load the file using lief
    binary = None
    binary_format = None
    try:
        binary = lief.parse(filepath)
        # Check the file type
        if isinstance(binary, lief.ELF.Binary):
            binary_format = "ELF"
        elif isinstance(binary, lief.PE.Binary):
            binary_format = "PE"
        elif isinstance(binary, lief.MachO.Binary):
            binary_format = "MACH-O"
        else:
            return (None, "Unknown Executable Type")
    except Exception as e:
        return (None, f"error \"{e}\" : lief can't open the file : {filepath}")
    
    # get imported and exported functions
    file = {"filename": real_filepath[real_filepath.rfind('/')+1:],
            "filepath": filepath,
            "real_filepath": real_filepath,
            "relative_filepath": filepath[len(directory):],
            "filehash": sha256sum_file(real_filepath),
            "filetype": get_file_type(directory, real_filepath),
            "imports": None,
            "exports": None }
    if binary_format == "ELF":
        file["imports"] = lief_get_elf_imported_functions(binary)
        file["exports"] = lief_get_elf_exported_functions(binary)
    else:
        pass # to do PE and MACH-O
    return file
    

def gen_files(directory, disassembler="lief"):
    
    # looking for ELF
    compiled_types = ["application/x-object", "application/x-sharedlib", "application/x-executable"]
    # list all the files and find the ones that corresponds to the defined types here.
    filenames = [file for file in list_files(directory) if get_file_type(directory, file) in compiled_types]
    
    # for each file build the node object
    files = []
    if disassembler == "lief":
        for filename in filenames:
            files.append(lief_gen_file(directory, filename))
    elif disassembler== "objdump":
        pass
    return files

def gen_nodes(files):
    nodes = {}
    for file in files:
        nodes[file["real_filepath"]] = file
    return nodes

    return links

def sym_map(fs_dir, out):
    files = gen_files(fs_dir)
    nodes = gen_nodes(files)
    to_graph_app(fs_dir, out, nodes)

