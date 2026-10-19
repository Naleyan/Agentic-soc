MITRE ATT&CK est une base de connaissances mondiale documentant les tactiques, techniques et procédures (TTP) réellement observées lors d'attaques cyber.

Elle structure l'activité adverse selon trois niveaux hiérarchiques :
- tactique (le pourquoi) : représente l'objectif stratégique de l'attaquant, par exemple, l'exfiltration de données ou la persistance dans un système.
- technique (le comment) : décrit comment l'attaquant atteint son objectif tactique, par exemple, l'utilisation de logiciels malveillants ou l'exploitation de vulnérabilités.
- procédure (l'implémentation concrète) : détaille les étapes spécifiques et les méthodes utilisées par l'attaquant pour mettre en oeuvre une attaque

MITRE ATT&CK transforme des lignes de logs illisibles en code standardisés pour que tous les agents parlent la même langue et fournit la grille d'évaluation pour prouver que la détection fonctionne.

Rôles dans le projet : 
Ce sera le langage pivot. Il permet à l'Agent Corrélation de traduire des flux de logs bruts hétérogènes en identifiants standardisés exploitables par l'Agent Décision, faisant ainsi le pont direct vers les contre-mesure MITRE D3FEND.
Le cadre des scénarios d'attaque suivra les quatre scénarios offensifs de test imposés en phase 1. 
La métrique d'évaluation sert à calculer le taux d'efficacité du système : 

Couverture ATT&CK = Nombre de techniques détectées par l'agent / Nombre de techniques réellement jouées dans les tests

MITRE D3FEND est une base de connaissances qui standardisent l'ensemble des techniques de contre-mesure et de défense cyber (Blue Team).

Alors qu'ATT&CK décrit comment un attaquant agit, d3FEND décrit formellement comment un système se défend et modélise les relations logiques entre les composants du système d'information, les menaces et les mécanismes de protection. 

D3FEND est découpé en 6 grandes tactiques défensives contenant chacune des techniques concrètes : 
- Modéliser : cartographier les actifs, les 