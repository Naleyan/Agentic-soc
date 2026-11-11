# Journal de bord — Projet cyberdéfense multi-agents (Phase 1)

## Semaine du 20 au 26 octobre

**Décisions prises :**
- Découpage en 3 binômes par chantier (Plateforme / Agents / Red team & éval) plutôt que par étape, pour avancer en parallèle
- ATT&CK et D3FEND adoptés comme langage commun du projet

**Impasses rencontrées :**
- —

**Temps passé :** ~4 h/pers — cadrage, glossaire, premières lectures

## Semaine du 27 octobre au 2 novembre

**Décisions prises :**
- LangGraph pressenti comme framework (contrôle du flux, traçabilité, validation humaine natifs)
- AutoGen écarté (mode maintenance depuis fin 2025) ; MAF écarté (orienté .NET/Azure, hors de notre périmètre Python)

**Impasses rencontrées :**
- Premières sections rédigées sans sources — à réétayer entièrement (retour prof)

**Temps passé :** ~5 h/pers — état de l'art, scénarios, métriques, matrice v1

## Semaine du 3 au 9 novembre

**Décisions prises :**
- Plan réorganisé en 2 parties (État de l'art / Conception) pour supprimer les allers-retours de thèmes signalés par le prof dans la note de cadrage 
- Ajout d'une section Plateforme et d'une section Architecture dans la note de cadrage

**Impasses rencontrées :**
- Chiffres d'études cités à vérifier à la source avant de les conserver (demande du prof)

**Temps passé :** ~7 h/pers — corrections de la note de cadrage

## Semaine du 10 au 16 novembre

**Décisions prises :**
- Communication inter-agents par état partagé (LangGraph), pas de message bus — flux séquentiel, traçabilité, complexité évitée
- Développement incrémental : squelette déterministe de bout en bout d'abord, LLM ajouté seulement quand une règle ne suffit plus
- Perception en règles (pas de LLM) car elle lit des logs en partie contrôlés par l'attaquant (risque d'injection, ATLAS)

**Impasses rencontrées :**

**Temps passé :**
