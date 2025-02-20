import os
import json
import sys


def read_bindiff_file(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

def parse_bindiff_output(lines):
    data = {
        "statistics": {},
        "functions": [],
        "unmatched_primary": [],
        "unmatched_secondary": []
    }

    section = None
    for line in lines:
        line = line.strip()
        if line.startswith("--------- statistics ---------"):
            section = "statistics"
        elif line.startswith("--------- matched"):
            section = "functions"
        elif line.startswith("--------- unmatched primary"):
            section = "unmatched_primary"
        elif line.startswith("--------- unmatched secondary"):
            section = "unmatched_secondary"
        elif section == "statistics" and line:
            line_subparts = line.split(":")
            key = ''.join(line_subparts[:-1])
            value = line_subparts[-1]
            data["statistics"][key.strip()] = value.strip()
        elif section == "functions" and line:
            parts = line.split('\t')
            if len(parts) >= 10:
                data["functions"].append({
                    "address_primary": parts[0],
                    "address_secondary": parts[1],
                    "similarity": parts[2],
                    "confidence": parts[3],
                    "type": parts[8],
                    "name_primary": parts[9],
                    "name_secondary": parts[10]
                })
        elif section == "unmatched_primary" and line:
            parts = line.split('\t')
            if len(parts) >= 4:
                data["unmatched_primary"].append({
                    "address": parts[0],
                    "name": parts[3]
                })
        elif section == "unmatched_secondary" and line:
            parts = line.split('\t')
            if len(parts) >= 4:
                data["unmatched_secondary"].append({
                    "address": parts[0],
                    "name": parts[3]
                })
    return data

def generate_html(all_data):
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Bindiff Results</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 0px;
                padding: 0px;
                display: flex;
                height: 100vh;
            }
            .sidebar {
                width: 20vw;
                background-color: #f4f4f4;
                padding: 20px;
                box-shadow: 2px 0 5px rgba(0,0,0,0.1);
                box-sizing: border-box;
            }
            .sidebar h2 {
                margin-top: 0px;
            }
            .sidebar ul {
                list-style-type: none;
                padding: 0px;
                margin: 0px;
                overflow: scroll;
                height: 90vh;
            }
            .sidebar li {
                padding: 10px;
                border-radius: 5px;
                cursor: pointer;
            }
            .sidebar li:hover {
                background-color: #ddd;
            }
            .main {
                width: 80vw;
                display: flex;
                box-sizing: border-box;
                position: relative;
            }
            .top-main {
                width: 80vw;
                height: 50vh;
                position: absolute;
            }

            .stats-main {
                width: calc(60vw - 20px);
                height: 50vh;
                position: absolute;
                top: 0px;
                left: 0px;
            }
            .unmatch-prim-main {
                width: 20vw;
                height: 25vh;
                position: absolute;
                top: 0px;
                right: 0px;
            }
            .unmatch-second-main {
                width: 20vw;
                height: 25vh;
                position: absolute;
                top: 25vh;
                right: 0px;
            }
            .bottom-main {
                width: 80vw;
                height: calc(50vh - 20px);
                position: absolute;
                top: 50vh;
                left: 0px;
                overflow: scroll;
            }
            .section {
                width: 100%;
                height: 100%;
                border-radius: 10px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                display: none;
                flex-direction: column;
            }
            .section-content {
                display: block; 
                height: 100%;
                overflow: scroll;
            }
            .section h2 {
                background-color: #007BFF;
                color: white;
                padding: 10px 20px;
                margin: 0;
            }
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th, td {
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }
            th {
                background-color: #f2f2f2;
            }
            .unmatched {
                background-color: #ffcccc;
            }
            .matched {
                background-color: #ccffcc;
            }
        </style>
        <script>
            function showFile(index) {
                const sections = document.querySelectorAll('.section');
                sections.forEach((section, i) => {
                    section.style.display = section.id === 'section-'+index ? 'flex' : 'none';
                });
            }
        </script>
    </head>
    <body>
        <div class="sidebar">
            <h2>Files</h2>
            <ul>
    """

    for index, (filename, _) in enumerate(all_data):
        html += f"<li onclick=\"showFile({index})\">{filename}</li>"

    html += """
            </ul>
        </div>
        <div class="main">
        <div class="top-main">
        <div class="stats-main">
    """

    for index, (filename, data) in enumerate(all_data):
        # Statistics section
        html += f"<div class='section section-stats' id='section-{index}'><h2>{filename} - Statistics</h2><div class='section-content'>"
        html += "<table><tr><th>Metric</th><th>Value</th></tr>"
        for key, value in data["statistics"].items():
            html += f"<tr><td>{key}</td><td>{value}</td></tr>"
        html += "</table></div></div>"
    html += """</div><div class="unmatch-prim-main">"""

    for index, (filename, data) in enumerate(all_data):
        # Unmatched functions section (Primary)
        html += f"<div class='section section-unmatch-prim' id='section-{index}'><h2>Unmatched functions (Primary)</h2><div class='section-content'>"
        html += "<table><tr><th>Address</th><th>Name</th></tr>"
        for func in data["unmatched_primary"]:
            html += f"<tr><td>{func['address']}</td><td>{func['name']}</td></tr>"
        html += "</table></div></div>"
    html += """</div><div class="unmatch-second-main">"""

    for index, (filename, data) in enumerate(all_data):
        # Unmatched functions section (Secondary)
        html += f"<div class='section section-unmatch-second' id='section-{index}'><h2>Unmatched functions (Secondary)</h2><div class='section-content'>"
        html += "<table><tr><th>Address</th><th>Name</th></tr>"
        for func in data["unmatched_secondary"]:
            html += f"<tr><td>{func['address']}</td><td>{func['name']}</td></tr>"
        html += "</table></div></div>"
    html += """</div><div class="bottom-main">"""

    for index, (filename, data) in enumerate(all_data):
        # Functions section
        html += f"<div class='section' id='section-{index}'><h2>Matched functions</h2><div class='section-content'>"
        html += "<table><tr><th>Similarity</th><th>Confidence</th><th>Primary Address</th><th>Primary Name</th><th>Secondary Address</th><th>Secondary Name</th><th>Type</th></tr>"
        for func in data["functions"]:
            similarity = float(func['similarity'])
            color = f"rgb({int(200 * (1 - similarity))}, {int(200 * similarity)}, 40)"
            html += f"<tr style='background-color: {color};'><td>{func['similarity']}</td><td>{func['confidence']}</td><td>{func['address_primary']}</td><td>{func['name_primary']}</td><td>{func['address_secondary']}</td><td>{func['name_secondary']}</td><td>{func['type']}</td></tr>"
        html += "</table></div></div>"

    html += """
        </div>
    </body>
    </html>
    """

    return html

def process_bindiff_files(path, outfile):
    if outfile == None:
        outfile = "bindiff_results.html"
    all_data = []
    if os.path.isfile(path):
        # Si le chemin est un fichier, traitez ce fichier uniquement
        if path.endswith(".results"):
            lines = read_bindiff_file(path)
            data = parse_bindiff_output(lines)
            all_data.append((path, data))
    elif os.path.isdir(path):
        # Si le chemin est un répertoire, parcourez récursivement les fichiers
        for root, _, files in os.walk(path):
            for filename in files:
                if filename.endswith(".results"):
                    file_path = os.path.join(root, filename)
                    lines = read_bindiff_file(file_path)
                    data = parse_bindiff_output(lines)
                    all_data.append((file_path[len(path):], data))
    else:
        raise ValueError("Le chemin fourni n'est ni un fichier ni un répertoire valide.")


    html_content = generate_html(all_data)

    with open(outfile, "w") as file:
        file.write(html_content)
    return outfile


# Example usage
# process_bindiff_files(sys.argv[1])
