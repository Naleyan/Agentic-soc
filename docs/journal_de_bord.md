# Journal de bord — Projet cyberdéfense multi-agents (Phase 1)

## Semaine du 20 au 26 octobre

**Décisions prises :**
- Organisation de l'équipe : découpage en 3 binômes par chantier (Plateforme / Agents / Red team & évaluation) plutôt que par étape du sujet, pour avancer en parallèle

**Impasses rencontrées :**
- —

**Temps passé :** ~4 h/pers — cadrage, glossaire des termes, premières lectures

## Semaine du 27 octobre au 2 novembre

**Décisions prises :**
- Framework d'agents : LangGraph pressenti (contrôle du flux, traçabilité et validation humaine natifs) ; AutoGen écarté (mode maintenance depuis fin 2025) 

**Impasses rencontrées :**
- Note de cadrage : premières sections rédigées sans sources — à réétayer entièrement (retour du prof)

**Temps passé :** ~7 h/pers — état de l'art, scénarios d'attaque, métriques, matrice d'autonomie v1

## Semaine du 3 au 9 novembre

**Décisions prises :**
- Note de cadrage : ajout d'une section Plateforme
- Scénarios d'attaque : ajout d'un 4ᵉ scénario (ransomware simulé, T1486) pour couvrir la tactique Impact

**Impasses rencontrées :**
- Note de cadrage, analyse critique : chiffres d'études cités à vérifier à la source avant de les conserver (demande du prof)

**Temps passé :** ~5 h/pers — corrections de la note de cadrage suite aux retours

## Semaine du 10 au 16 novembre

**Décisions prises :**
- Architecture des agents : début de la conception de l'architecture multi-agents (6 agents : Perception, Corrélation, Investigation, Décision, Action, Mémoire/Audit) ; premier schéma produit
- Architecture des agents : développement incrémental retenu — squelette déterministe de bout en bout d'abord, LLM ajouté seulement quand une règle ne suffit plus
- Architecture des agents : l'agent Perception restera en règles (pas de LLM), car il lit des logs en partie contrôlés par l'attaquant (risque d'injection de prompt, référentiel ATLAS)

**Impasses rencontrées :**

**Temps passé :** 
