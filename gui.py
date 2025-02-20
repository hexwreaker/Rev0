import tkinter as tk
from tkinter import messagebox, filedialog
import webbrowser
import subprocess
import networkx as nx
import plotly.graph_objs as go
import plotly.offline as pyo
from rev0 import symap

# Fonctions pour l'interface graphique
def execute_symap():
    filesys = entry_filesys.get()
    out_filepath = entry_out.get()
    if filesys:
        if out_filepath:
            symap(filesys, out_filepath)
        else:
            symap(filesys, None)
        messagebox.showinfo("Succès", "Commande exécutée avec succès.")
        if out_filepath:
            webbrowser.open(out_filepath)
        else:
            webbrowser.open("symap.html")
    else:
        messagebox.showerror("Erreur", "Veuillez spécifier le répertoire racine du système de fichiers.")

def select_filesys():
    filesys = filedialog.askdirectory()
    if filesys:
        entry_filesys.delete(0, tk.END)
        entry_filesys.insert(0, filesys)

def select_out_file():
    out_filepath = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files", "*.html")])
    if out_filepath:
        entry_out.delete(0, tk.END)
        entry_out.insert(0, out_filepath)

def function_two():
    # Exemple de deuxième fonction
    return "Fonction deux appelée"

def function_three():
    # Exemple de troisième fonction
    return "Fonction trois appelée"

def call_function_two():
    result = function_two()
    messagebox.showinfo("Résultat", result)

def call_function_three():
    result = function_three()
    messagebox.showinfo("Résultat", result)

def generate_graph():
    # Création d'un graphe simple avec networkx
    G = nx.Graph()
    G.add_node(1, label="Noeud 1")
    G.add_node(2, label="Noeud 2")
    G.add_node(3, label="Noeud 3")
    G.add_edge(1, 2)
    G.add_edge(2, 3)
    G.add_edge(3, 1)

    # Création des positions pour les nœuds
    pos = nx.spring_layout(G)

    # Création des traces pour les nœuds et les liens
    edge_trace = go.Scatter(
        x=[],
        y=[],
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines')

    node_trace = go.Scatter(
        x=[],
        y=[],
        text=[],
        mode='markers+text',
        textposition='top center',
        hoverinfo='text',
        marker=dict(
            showscale=True,
            colorscale='YlGnBu',
            size=10,
            colorbar=dict(
                thickness=15,
                title='Node Connections',
                xanchor='left',
            ),
            line=dict(width=2)))

    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_trace['x'] = edge_trace['x'] + [x0, x1, None]
        edge_trace['y'] = edge_trace['y'] + [y0, y1, None]

    for node in G.nodes():
        x, y = pos[node]
        node_trace['x'] = node_trace['x'] + [x]
        node_trace['y'] = node_trace['y'] + [y]
        node_trace['text'] = node_trace['text'] + [G.nodes[node]['label']]

    # Création de la figure
    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=0, l=0, r=0, t=0),
                        xaxis=dict(showgrid=False, zeroline=False),
                        yaxis=dict(showgrid=False, zeroline=False)
                    ))

    # Ajout d'un callback pour afficher un message lorsqu'un nœud est cliqué
    fig.data[1].on_click(lambda trace, points, selector: messagebox.showinfo("Info", f"Noeud cliqué : {points.point_inds[0] + 1}"))

    # Affichage du graphique dans un fichier HTML
    pyo.plot(fig, filename='network_graph.html', auto_open=True)

# Création de la fenêtre principale
root = tk.Tk()
root.title("Application Interactive")

# Création des champs de saisie pour les paramètres de la commande
tk.Label(root, text="Répertoire racine du système de fichiers").pack()
entry_filesys = tk.Entry(root)
entry_filesys.pack()
tk.Button(root, text="Sélectionner un dossier", command=select_filesys).pack()

tk.Label(root, text="Chemin du fichier de sortie (optionnel)").pack()
entry_out = tk.Entry(root)
entry_out.pack()
tk.Button(root, text="Sélectionner un fichier de sortie", command=select_out_file).pack()

# Création des boutons
tk.Button(root, text="SYMAP", command=execute_symap).pack()
tk.Button(root, text="Appeler Fonction 2", command=call_function_two).pack()
tk.Button(root, text="Appeler Fonction 3", command=call_function_three).pack()
tk.Button(root, text="Afficher le graphe", command=generate_graph).pack()

# Lancement de la boucle principale
root.mainloop()
