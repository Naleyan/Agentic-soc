# Référentiels de sécurité : MITRE ATT&CK, D3FEND et ATLAS

---

## 1. MITRE ATT&CK (Taxonomie offensive)

**MITRE ATT&CK** est une base de connaissances mondiale documentant les tactiques, techniques et procédures (TTP) réellement observées lors d'attaques cyber.

### Structure hiérarchique
* **Tactique (*le pourquoi*)** : représente l'objectif stratégique de l'attaquant.
* **Technique (*le comment*)** : décrit comment l'attaquant atteint son objectif tactique.
* **Procédure (*l'implémentation concrète*)** : détaille les étapes spécifiques et les commandes précises utilisées par l'attaquant pour mettre en œuvre une attaque.

> MITRE ATT&CK transforme des lignes de logs bruts en codes standardisés pour que tous les agents partagent le même langage, et fournit la grille d'évaluation pour prouver l'efficacité de la détection.

### Rôles dans le projet
* Ce sera le langage de pivot. Il permet à l'Agent Corrélation de traduire des flux de logs bruts hétérogènes en identifiants standardisés exploitables par l'Agent Décision, faisant ainsi le pont direct vers les contre-mesures MITRE D3FEND.
* Le cadre des scénarios d'attaque suivra les 4 scénarios offensifs de test imposés en phase 1.
* La métrique d'évaluation sert à mesurer le taux d'efficacité du système :

"""
$$\text{Couverture ATT\&CK} = \frac{\text{Nombre de techniques détectées par l'agent}}{\text{Nombre de techniques réellement jouées dans les tests}}$$
"""
---

## 2. MITRE D3FEND (Taxonomie défensive)

**MITRE D3FEND** est une base de connaissances qui standardisent l'ensemble des techniques de contre-mesure et de défense cyber (*Blue Team*).

Alors qu'ATT&CK décrit comment un attaquant agit, D3FEND décrit comment un système se défend et modélise les relations logiques entre les composants du système d'information, les menaces et les mécanismes de protection.

### Les 6 tactiques défensives
* **Modéliser (*Model*)** : cartographier les actifs, les topologies réseau et les dépendances du SI.
* **Durcir (*Harden*)** : réduire la surface d'attaque et sécuriser les configurations en amont
* **Détecter (*Detect*)** : analyser les flux et les comportements suspects.
* **Isoler (*Isolate*)** : confiner une ressource suspecte ou compromise pour stopper la propagation.
* **Tromper (*Deceive*)** : induire l'attaquant en erreur ou le piéger (*honeypots*).
* **Expulser (*Evict*)** : supprimer la présence de l'attaquant du système.

### Rôles dans le projet
Le système doit couvrir 5 capacités de réaction imposées, correspondant directement aux nœuds D3FEND :
1. **Alerting** $\rightarrow$ Notification et rapport contextualisé vers l'opérateur humain.
2. **Quarantaine** $\rightarrow$ Isolation réseau d'une machine, d'un conteneur ou d'un utilisateur compromis.
3. **Reconfiguration filtrante** $\rightarrow$ Modification dynamique des règles de pare-feu (`nftables`/`iptables`).
4. **Patching** $\rightarrow$ Application automatisée ou assistée de correctifs logiciels et mises à jour sur les machines vulnérables.
5. **Instrumentation à la demande** $\rightarrow$ Déploiement dynamique d'un collecteur ou sniffer réseau pour approfondir une suspicion sans impacter la production.

> D3FEND est conçu pour s'interfacer avec ATT&CK : à chaque technique adverse détectée, le graphe associe un ensemble de contre-mesures techniquement viables pour l'Agent Décision.

---

## 3. MITRE ATLAS (Sécurité de l'IA)

**MITRE ATLAS** (*Adversarial Threat Landscape for Artificial-Intelligence Systems*) est une base de connaissances mondiale qui modélise les tactiques, techniques et procédures (TTP) ciblant spécifiquement les systèmes basés sur l'intelligence artificielle (apprentissage automatique, modèles génératifs et IA agentique).

Inspiré directement de la structure matricielle d'ATT&CK, il formalise comment un adversaire peut explorer, manipuler, compromettre ou contourner une IA ainsi que les comportements autonomes néfastes générés par celle-ci.

### Découpage et spécificités IA
* **Plateformes cibles** : *Predictive AI*, *Generative AI* et *Agentic AI* (systèmes multi-agents autonomes exploitant des outils et de la mémoire).
* **Tactiques spécialisées** :
  * Accès aux modèles et API (*AI Model Access*).
  * Exécution et persistance via injections directes ou indirectes (*LLM Prompt Injection*).
  * Empoisonnement de la mémoire et des outils (*AI Agent Context / Tool Poisoning*).
  * Évasion et contournement des filtres (*Defense Evasion* / *LLM Jailbreak*).
  * Impacts opérationnels et financiers (*Cost Harvesting*, déni de service, actions destructrices).

### Rôles dans le projet
* Le projet pose la question de la confiance accordée à une défense autonome. Il est impératif de protéger le réseau avec les agents mais aussi de protéger les agents contre des manipulations adverses.
* L'Agent Perception prend des flux et des logs bruts, un attaquant pourrait y insérer une invite malveillante (*Indirect Prompt Injection*) pour fausser le résultat de l'Agent Décision et forcer l'Agent Action à couper une machine saine du réseau.
* ATLAS illustre les dérives possibles lors des invocations d'outils système (*AI Agent Tool Invocation*), ce qui justifie la mise en place d'un arrêt d'urgence (*kill switch*), de fonctions de rollback et de la matrice d'autonomie (L0 à L4) pour éviter les fausses actions destructrices.
