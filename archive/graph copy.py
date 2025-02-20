
from dash import Dash, html
import dash_cytoscape as cyto
from pyvis.network import Network

def get_color_from_filetype(filetype):
    if "executable" in filetype:
        return "crimson"
    elif "sharedlib" in filetype:
        return "lightgreen"
    elif "object" in filetype:
        return "aliceblue"
    else:
        return "grey"

def to_graph_app(graph_name, nodes):

    # Create a network
    net = Network(select_menu=True)
    net.barnes_hut()
    # net.set_options('''
    # var options = {
    #   "physics": {
    #     "enabled": true,
    #     "solver": "forceAtlas2Based",
    #     "forceAtlas2Based": {
    #       "gravitationalConstant": -50,
    #       "centralGravity": 0.005,
    #       "springLength": 230,
    #       "springConstant": 0.18
    #     },
    #     "minVelocity": 0.75,
    #   }
    # }
    # ''')
    net.repulsion()

    # Track the degree of each node
    node_degrees = {file_data["real_filepath"]: 0 for file_data in nodes.values()}

    edges = {}
    # Add edges based on imports and exports
    for filename, file_data in nodes.items():
        for impname, imp in file_data["imports"].items():
            for filename2, file_data2 in nodes.items():
                if filename != filename2:
                    for expname, exp in file_data2["exports"].items():
                        if impname == expname:
                            
                            # Create an edge key using source and destination
                            edge_key = (file_data["real_filepath"], file_data2["real_filepath"])
                            
                            if edge_key not in edges:
                                # Add a new edge with weight 1
                                edges[edge_key] = {
                                    "title": f"{file_data["relative_filepath"]} import from {file_data2["relative_filepath"]}",
                                    "import_desc": f"<div classname=\"edge-panel-title\" style=\"position: sticky; background-color: white; top: 0px; padding: 10px 0px; \"><div style='width: 100%; border-bottom: 2px solid lightgreen;'><b style='font-size: 1.5rem;'>IMPORTS</b></div><div style=\"font-size: 1.0rem;\"><b><br>{file_data["relative_filepath"]}</b> --import--> <b>{file_data2["relative_filepath"]}</b></div></div>",
                                    "content": f"<div classname=\"edge-panel-symbol\">{impname}</div>",
                                    "weight": 0.5
                                }
                            else:
                                # Append to the existing edge's title and increment weight
                                edges[edge_key]["content"] += f"<div classname=\"edge-panel-symbol\">{impname}</div>"
                                edges[edge_key]["weight"] += 0.03

                            # Update node degrees
                            node_degrees[file_data["real_filepath"]] += 1
                            node_degrees[file_data2["real_filepath"]] += 1

    # Add nodes to the graph with size based on degree
    for filename, file_data in nodes.items():
        degree = node_degrees[file_data["real_filepath"]]
        net.add_node(
            file_data["real_filepath"],
            label=file_data["relative_filepath"],
            title=f"{file_data['relative_filepath']} ({file_data['filetype']})",
            color=get_color_from_filetype(file_data['filetype']),
            size=15 + degree/100,  # Base size 10, increase with degree
            filename=file_data['filename'],
            real_filepath=file_data['real_filepath'],
            relative_filepath=file_data['relative_filepath'],
            filetype=file_data['filetype'],
            imports = ''.join([f"<div classname=\"panel-import-symbol\">{impname}</div>" for impname, imp in file_data["imports"].items()]),
            exports = ''.join([f"<div classname=\"panel-export-symbol\">{expname}</div>" for expname, exp in file_data["exports"].items()]),
        )

    # Add the edges to the graph with weights
    for (source, target), edge_data in edges.items():
        net.add_edge(
            source,
            target,
            title=edge_data["title"],
            import_desc=edge_data["import_desc"],
            content=edge_data["content"],
            color="black",
            width=edge_data["weight"]  # Use the weight value
        )


    # Generate and display the visualization
    net.show("graph.html", notebook=False)
    
    custom_js = """
    <script type="text/javascript">
        // Wait for the DOM content to load
        document.addEventListener("DOMContentLoaded", function () {
            // Add som style css
            var card = document.getElementsByClassName("card")[0];
            card.style.position = 'absolute'
            card.style.width = '75vw'
            card.style.height = '100vh'
            card.style.top = '0px'
            card.style.right = '0px'

            // Add edge panel
            // Get the network container
            var networkContainer = document.getElementById("mynetwork");
            networkContainer.style.margin = 'auto'
            networkContainer.style.position = 'absolute'
            networkContainer.style.top = '0px'
            networkContainer.style.height = '99vh'
            networkContainer.style.border = 'none'
            networkContainer.style.padding = '4px' 

            // Add a div for displaying edge details
            var edgePanel = document.createElement("div");
            edgePanel.id = "edgePanel";
            edgePanel.style.position = "absolute";
            edgePanel.style.top = "0px";
            edgePanel.style.left = "0px";
            edgePanel.style.width = "25vw";
            edgePanel.style.height = "100vh";
            edgePanel.style.overflow = "scroll";
            edgePanel.style.padding = "0px 10px 10px 10px";
            edgePanel.style.backgroundColor = "rgba(255, 255, 255, 0.9)";
            edgePanel.style.border = "1px solid #ccc";
            edgePanel.style.display = "none";  // Initially hidden
            document.body.appendChild(edgePanel);

            // Add a div for displaying edge details
            var nodePanel = document.createElement("div");
            nodePanel.id = "nodePanel";
            nodePanel.style.position = "absolute";
            nodePanel.style.top = "0px";
            nodePanel.style.left = "0px";
            nodePanel.style.width = "25vw";
            nodePanel.style.height = "30vh";
            nodePanel.style.overflow = "scroll";
            nodePanel.style.padding = "10px";
            nodePanel.style.backgroundColor = "rgba(255, 255, 255, 0.9)";
            nodePanel.style.border = "1px solid #ccc";
            nodePanel.style.display = "none";  // Initially hidden

            // Add an import div into nodePanel
            var importsPanel = document.createElement("div");
            importsPanel.id = "importsPanel";
            importsPanel.style.position = "absolute";
            importsPanel.style.top = "30vh";
            importsPanel.style.left = "0px";
            importsPanel.style.width = "25vw";
            importsPanel.style.height = "35vh";
            importsPanel.style.overflow = "scroll";
            importsPanel.style.padding = "0px 10px 10px 10px";
            importsPanel.style.backgroundColor = "rgba(255, 255, 255, 0.9)";
            importsPanel.style.border = "1px solid #ccc";
            importsPanel.style.display = "none";  // Initially hidden

            // Add an export div into nodePanel
            var exportsPanel = document.createElement("div");
            exportsPanel.id = "exportsPanel";
            exportsPanel.style.position = "absolute";
            exportsPanel.style.top = "65vh";
            exportsPanel.style.left = "0px";
            exportsPanel.style.width = "25vw";
            exportsPanel.style.height = "35vh";
            exportsPanel.style.overflow = "scroll";
            exportsPanel.style.padding = "0px 10px 10px 10px";
            exportsPanel.style.backgroundColor = "rgba(255, 255, 255, 0.9)";
            exportsPanel.style.border = "1px solid #ccc";
            exportsPanel.style.display = "none";  // Initially hidden

            document.body.appendChild(nodePanel);
            document.body.appendChild(importsPanel);
            document.body.appendChild(exportsPanel);

            var otherEdges = []

            // Add event listener to the network
            network.on("click", function (params) {
                // Reset all edges to remove arrows and set default style
                for (let i in otherEdges) {
                    network.body.data.edges.update({
                        id: otherEdges[i],
                        arrows: { from: { enabled: false } }, // Disable arrows
                        color: "black", // Reset to default color
                        width: 1 // Reset to default width
                    });
                };

                if (params.nodes.length > 0) {
                    network.selectNodes([params.nodes[0]]);
                    var nodeId = params.nodes[0]; // Get the clicked node
                    var nodeData = network.body.data.nodes.get(nodeId);
                    
                    // Display the node details in the node panel
                    nodePanel.innerHTML = "<div style='width: 100%; border-bottom: 2px solid lightgreen;'><b style='font-size: 1.5rem;'>File details:</b></div><br>" + 
                                        "<div style='display: inline-block; user-select: none;'>Filename :&ensp;</div><b>" + nodeData.filename + "</b><br>" + 
                                        "<div style='display: inline-block; user-select: none;'>Relative filepath :&ensp;</div><b style='font-size: 0.8rem;'>" + nodeData.relative_filepath + "</b><br>" + 
                                        "<div style='display: inline-block; user-select: none;'>Real filepath :&ensp;</div><b style='font-size: 0.8rem;'>" + nodeData.real_filepath + "</b><br>" + 
                                        "<div style='display: inline-block; user-select: none;'>Type of file :&ensp;</div><b>" + nodeData.filetype + "</b><br>" + ""
                                        //"Type of file: " + nodeData.filetype;
                    
                    // Display the node imports
                    importsPanel.innerHTML = "<div  style='position: sticky; background-color: white; top: 0px; padding: 10px 0px; width: 100%; border-bottom: 2px solid lightgreen;'><b style='font-size: 1.5rem;'>Imports:</b></div><br>" + 
                                        "<div style='overflow: scroll; '>" + nodeData.imports + "</div>";

                    // Display the node exports
                    exportsPanel.innerHTML = "<div style='position: sticky; background-color: white; top: 0px; padding: 10px 0px; width: 100%; border-bottom: 2px solid lightgreen;'><b style='font-size: 1.5rem;'>Exports:</b></div><br>" + 
                                        "<div style='overflow: scroll; '>" + nodeData.exports + "</div>";
                    
                    // Highlight edges connected to the clicked node
                    var connectedEdges = network.getConnectedEdges(nodeId);
                    connectedEdges.forEach(function (edgeId) {
                        otherEdges.push(edgeId)
                        // Get the edge data
                        var edgeData = network.body.data.edges.get(edgeId);
                        // Update the edge to show arrow directions
                        network.body.data.edges.update({
                            id: edgeId,
                            arrows: { from: { enabled: true, scaleFactor: 1.5 } }, // Add a larger arrow
                            color: "red", // Highlight edge color
                            width: edgeData.width * 1.5 // Make edge thicker
                        });
                    });

                    nodePanel.style.display = "block";  // Show the node panel
                    importsPanel.style.display = "block";  // Show the node panel
                    exportsPanel.style.display = "block";  // Show the node panel
                    edgePanel.style.display = "none";  // Mask the node panel
                }
                else if (params.edges.length > 0) {
                    network.selectEdges([params.edges[0]]);
                    var edgeId = params.edges[0]; // Get the clicked edge
                    var edgeTitle = network.body.data.edges.get(edgeId).title;
                    var edgeImport_desc = network.body.data.edges.get(edgeId).import_desc;
                    var edgeContent = "<div style='overflow: scroll; '>" + network.body.data.edges.get(edgeId).content + "</div>";
                    // Display the edge title in the panel
                    edgePanel.innerHTML = edgeImport_desc + "<br>" + edgeContent;
                    edgePanel.style.display = "block";  // Show the panel
                    nodePanel.style.display = "none";  // Mask the panel
                    importsPanel.style.display = "none";  // Show the node panel
                    exportsPanel.style.display = "none";  // Show the node panel

                    // Update the clicked edge to show arrow direction
                    otherEdges.push(edgeId)
                    network.body.data.edges.update({
                        id: edgeId,
                        arrows: { from: { enabled: true, scaleFactor: 1.5 } }, // Add a larger arrow
                        color: "red", // Highlight edge color
                        width: 3 // Make edge thicker
                    });
                }
                else {
                    neighbourhoodHighlight({
                        nodes: []
                    });
                }

            });
        });
    </script>
    """
    with open("graph.html", "r") as file:
        html_content = file.read()

    # Inject the custom JavaScript before the closing </body> tag
    html_content = html_content.replace("</body>", custom_js + "\n</body>")

    # Save the modified HTML
    with open("graph.html", "w") as file:
        file.write(html_content)

def to_obsidian():
    pass
