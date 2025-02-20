
> Author : hexwreaker

# Rev0 : reverse engineering framework

## Features

#### Symbols graph helper

On Linux, binaries are linked to libs. The problem is that we can't know what lib contains the linked function, even is some library names are included into the binary.
This helper help the user to find the libs that contains function used by binaries, in a project.

1. Deduce import links between libraries and binaries.
1. Generate a graphic "link map" to overview the result.
1. Allow the user to click on a link-map 's cell to start reversing the binary using his preferred software.

## Code maps

1. /rev0.py : main command script.
#### Diffing
1. /bindiff_to_html.py : convert the bindiff result in HTML
1. /diff_bin.py : binary diffing 
1. /diff_filesys.py : filesystem diffing 
#### Symbols graph
1. /maproject.py : main symbols graph script
1. /graph.py : export to graph 

## Requirements 
#### Python
1. lief
1. capstone
1. magic
1. hashlib
1. dash
1. dash_cytoscape
1. pyvis

#### Other tools
1. gnu diffutils
1. Quarkslab python-binexport
1. Zynamics's bindiff
