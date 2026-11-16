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
- Implémentation des VLAN de la plateforme d'expérimentation

*Équipe agents d'IA :*
- Perception et Corrélation en règles déterministes, sans LLM : résultats reproductibles et explicables, comme l'exige un SOC
- Perception lit les alertes JSON de Wazuh (seule source de vérité de l'architecture v2) et les traduit en une « fiche événement » unique (`docs/event_schema.md`) : des faits, pas d'interprétation
- Corrélation : un incident progresse en 3 étapes, `attempt` (T1110), `compromise` (T1078) puis `persistence` (T1053), pour enchaîner les événements au lieu de re-détecter ce que Wazuh voit déjà
- Seuil de force brute : 5 échecs en 10 minutes, réglage par défaut de fail2ban ; le score de confiance du prototype, arbitraire, est supprimé pour limiter les fausses actions
- Tests sans Wazuh, sur alertes simulées : 26 tests réussis ; l'attaque du scénario 1 donne 1 incident, le trafic légitime 0

**Impasses rencontrées :**

*Équipe agents d'IA :*
- Alertes Wazuh simulées à la main : format et numéros de règles à confirmer sur la vraie plateforme ; MTTD et MTTR non mesurables pour l'instant
- Jeu de test trop petit (2 fichiers) pour annoncer un taux de détection ou de faux positifs
- Incohérences entre documents à harmoniser : 3 plans d'adressage IP et 2 échelles d'autonomie (L0–L4 et N0–N3)

**Temps passé :** 
