## Revue intermédiaire — SOAR, XDR et IA agentique

O ct 19, 2026

Les agents LLM savent investiguer une alerte de niveau 1 de façon fiable s'ils sont structurés en rôles avec revue indépendante, mais aucun travail ne démontre encore une réponse autonome sûre. Cette revue s'appuie sur 12 papiers (2019–2026) lus en détail, pour le projet IMT Atlantique « Sécurité et IA agentique » avec Orange Innovation.

·

@Luce

## 1. Fondamentaux

Le SIEM et l'XDR détectent et corrèlent, le SOAR exécute ; l'IA agentique vise le maillon manquant entre les deux, l'investigation.

- SIEM : collecte, normalise et corrèle les journaux, surtout par des règles écrites par le SOC.

- XDR : extension de l'EDR qui corrèle nativement endpoint, réseau, identité, e-mail et cloud, et regroupe les alertes en incidents.

- SOAR : orchestration des outils, automatisation des tâches et réponse par playbooks. Islam et al. (2019) y incluent explicitement la coordination des experts humains.

- Agent IA : LLM doté d'outils (requêtes SIEM, CTI, annuaire) qui planifie, agit, observe et itère. Dans les travaux étudiés, il investigue et recommande, sans exécuter seul.


## L'agent IA s'insére entre la corrélation XDR et I'exécution SOAR

Architecture cible d'un SOC agentique · 6 composants

L'agent lit des alertes corrélées et des logs bruts, dont certains champs sont écrits par l'attaquant (voir section 4).

## 2. SOAR et XDR : ce que dit la recherche

La recherche SOAR est surtout conceptuelle, et la recherche XDR publique vient presque entièrement de Microsoft.

Islam, Babar, Nepal — revue multi-vocale de l'orchestration (ACM CSUR, 2019). 95 sources (43 académiques, 52 issues de la littérature grise), de 2007 à 2017. Les auteurs proposent une définition de l'orchestration : coordonner outils et experts pour produire et automatiser la réponse. Ils la structurent en trois fonctions (hub d'intégration, orchestration des workflows, réponse automatisée) et en cinq dimensions (environnement, stratégie d'automatisation, déploiement, mode de tâche, ressource). Les moteurs de l'orchestration sont le manque d'interopérabilité, la surcharge des analystes et la pénurie de compétences. Point de vigilance : automatiser sans planification revient à accélérer un mauvais processus.

Akbari Gurabi et al. — playbooks legacy vers CACAO par LLM (Fraunhofer, 2025). Le pipeline décompose la tâche en 4 sous-tâches, injecte des extraits du schéma CACAO dans le prompt, valide le résultat par un vérificateur syntaxique et boucle pour corriger. Sur 40 playbooks Phantom, Fortinet et Demisto, les erreurs syntaxiques baissent de 73 %


et tombent quasiment à zéro après 5 itérations avec GPT-4o. Le flot de contrôle est bien préservé (distance de graphe normalisée de 0,15). L'intérêt : le LLM intervient à la conception, et l'exécution reste déterministe.

Freitas & Gharib — GraphWeaver (Microsoft, 2024). C'est la corrélation de Defender XDR. Les alertes sont les nœuds d'un graphe ; deux alertes sont reliées si elles partagent une entité, parmi 17 types, chacun avec une priorité et une fenêtre temporelle. La CTI filtre les entités peu fiables, des garde-fous empêchent les incidents « trou noir », et un arbre couvrant minimal réduit le stockage d'un facteur 7,4. Résultat : 99 % de corrélations justes, à l'échelle de milliards d'alertes.

Freitas et al. — réponse guidée (CGR) et jeu GUIDE (Microsoft, 2024). Les auteurs jugent l'automatisation complète irréaliste, car il faudrait environ 99 % de confiance. CGR recommande donc à l'analyste un triage, des incidents similaires et une remédiation, avec un seuil de précision de 0,9. Le modèle est du ML classique (forêts aléatoires) et non un LLM. Triage : macro-F1 de 0,87 hors ligne, 41 % des incidents couverts en ligne ; 89 % d'avis positifs. Le jeu GUIDE (1 M d'incidents étiquetés, public sur Kaggle) est la seule base XDR réelle de cette taille.

## 3. Agents LLM pour le SOC

Un LLM seul échoue sur les investigations longues ; ce qui fonctionne, c'est la décomposition en rôles spécialisés, ancrée dans des outils typés, avec un état de l'enquête explicite.

Habibzadeh et al. — revue de 138 papiers (2025). Le nombre de travaux décroît nettement de la détection vers la réponse : la réponse, là où se trouve le SOAR, est le maillon le moins étudié. En détection, le prompt engineering seul reste loin des modèles entraînés.

Singh et al. — usage réel en SOC (CSIRO / eSentire, 2025). 3 090 requêtes de 45 analystes à GPT-4, sur 10 mois. Les usages dominants sont l'explication de commandes (31 %), la rédaction (22 %) et l'analyse de scripts (11 %). Les échanges sont courts (2 à 3 tours) et 4 % seulement des requêtes demandent un verdict : les analystes veulent des preuves, pas une décision.

Wei et al. — CORTEX (2025). Le triage est découpé en quatre rôles : orchestrateur, analyse comportementale qui route l'alerte vers 7 workflows métier, acquisition de preuves via des outils MCP, puis raisonnement qui produit un rapport JSON auditable. La politique d'escalade est conservatrice. Le système est évalué sur des traces de SOC réelles.


Lin et al. — IRCopilot (ACM CCS 2025). Sur un benchmark de 12 cas et 130 sous-tâches, aucun LLM seul ne résout plus de 5 cas. La première cause d'échec est une mauvaise stratégie (74 échecs sur 174). IRCopilot sépare quatre sessions : Planner (arbre de tâches), Generator (commandes), Reflector (hallucinations, fuites de données) et Analyst. Sans Planner, le taux de sous-tâches réussies tombe à 43 %.

Tsegai et al. — AIDA (Virginia Tech / Google, 2026). Les auteurs comparent 5 stratégies sur 1 247 alertes rejouées dans un SIEM Wazuh. Toutes ratent au moins 40 % des attaques, pour trois raisons : une recherche vide est prise pour une preuve d'innocuité, l'auto- relecture casse plus de bonnes décisions qu'elle n'en corrige (79 contre 16), et classer une alerte ne déclenche pas une enquête plus poussée. AIDA corrige ces défauts avec un Stratège qui s'engage sur une thèse, un Exécuteur sans LLM, un Adversaire en contexte séparé et un Juge qui exige plus de preuves pour classer que pour escalader.

| Système | Tâche | Avant (agent unique) Après | Coût du gain |
| --- | --- | --- | --- |
| CORTEX Triage |   | F1 actionnable 0,66 ; F1 0,78 ; faux | Latence × 3,4 ; tokens |
|   | d'alertes | faux positifs 24,9 % positifs 14,2 % | × 5,7 |
| IRCopilot Réponse à |   | 58 à 87 % de sous- × 1,14 à × 1,50 | Plus lent sur 8 cas sur |
|   | incident | tâches réussies | 12 |
| AIDA | Triage | F1 0,744 ; faux F1 0,958 ; faux | 18,4 % d'alertes |
|   | d'alertes | négatifs 40,4 % négatifs 3,1 % | escaladées ; ~0,11 $ |
|   |   |   | par alerte |

Avec AIDA, un modèle ouvert de 9B (Qwen3.5) égale GPT-4.1 : la structure compte plus que la taille du modèle.

## 4. Évaluation et risques

Les bancs d'essai sont récents et hétérogènes, et le principal risque spécifique au SOC est l'injection de prompt via les logs eux-mêmes.

ExCyTIn-Bench (Microsoft, ICML 2026). L'environnement est un tenant Azure avec 57 tables Sentinel et 8 chaînes d'attaque réelles rejouées. Les 589 questions de test sont générées à partir des graphes d'incidents, et une récompense partielle valorise les étapes intermédiaires. Le meilleur score est de 0,606 (Claude Opus 4.5), contre 0,293 pour GPT- 4o. La réussite dépend surtout de la capacité à écrire des requêtes SQL valides ; sans les tables d'alertes, les scores chutent.

Autres bancs. ALERT-BENCH (Tsegai et al.) mesure le triage dans un SIEM réel. Le benchmark IRCopilot couvre la réponse de bout en bout, et GUIDE le triage sur données réelles. CyberSOCEval (Meta) teste malware et CTI en QCM ; ce format est reproductible


mais éloigné d'un workflow interactif. Pour ce dernier, seuls le résumé et l'introduction ont été lus. Bonne pratique commune : mesurer ensemble le taux de faux négatifs et la charge envoyée aux analystes.

Pandey & Bhujang — injection via les logs (2026). Un attaquant écrit des instructions dans des champs qui seront journalisés : user-agent, URI, requête DNS, identifiant. L'étude couvre 4 classes d'attaque, 3 tâches et 4 défenses, sur GPT-4o-mini.

- Les ordres directs échouent (0 %), mais l'usurpation d'autorité fait passer 68 % des logs malveillants pour bénins sans défense.

- Le résumé est la tâche la plus exposée : jusqu'à 96 % de succès par imitation de structure, où l'attaque est omise sans même afficher « bénin ».

- Les défenses réduisent le succès moyen de 26,6 % à 11,8 %, jamais à zéro.

Autres risques relevés. Hallucinations et commandes fausses (IRCopilot), fuite de données vers le fournisseur du modèle (d'où le recours à des modèles locaux), corrélations erronées pouvant toucher des machines saines (GraphWeaver), et perte de confiance des analystes après une erreur isolée (Singh et al.). Aucun papier ne recommande un agent qui agit seul.

## 5. Synthèse et pistes pour le projet Orange

Le projet a intérêt à viser un agent d'investigation qui recommande une réponse au SOAR, pas un SOAR autonome.

## Ce qui fait consensus.

- 1. La structure (rôles, état explicite, revue indépendante) compte plus que le modèle.

- 2. Plus de raisonnement ou d'auto-relecture ne garantit pas une meilleure décision.

- 3. Le contexte XDR (alertes corrélées) et des outils typés sont indispensables.

- 4. L'humain garde les décisions à impact.

- 5. Les logs sont une entrée hostile.

Verrous ouverts. Passer du triage à la réponse réelle via le SOAR. Tester la robustesse

d'agents outillés face à l'injection : les études actuelles portent sur des LLM sans outils. Évaluer sur des données réalistes et mesurer l'effet sur les analystes. Réduire le coût des architectures multi-agents (latence × 3 à × 6). Compléter la génération de playbooks CACAO (agents, cibles, commandes).

## Pistes concrètes.

- Agent de type AIDA ou CORTEX dont la sortie est le choix d'un playbook SOAR existant avec ses paramètres, validé par un analyste.

- Preuves bénignes positives exigées avant tout classement en faux positif.


- Garde-fous anti-injection : exécuteur déterministe qui balise les champs, sortie contrainte, verdict bénin obligatoirement justifié par des champs cités.

- Évaluation sur ALERT-BENCH ou ExCyTIn-Bench (publics), avec faux négatifs, charge analyste et taux de succès d'injection.

À demander à Orange : quels SIEM et SOAR, quelles données accessibles, et quel niveau d'autonomie est acceptable ?

## Sources

- 1. Akbari Gurabi et al., From Legacy to Standard: LLM-Assisted Transformation of Cybersecurity Playbooks into CACAO Format, 2025 — arXiv:2508.03342 [URL 🔗](https://arxiv.org/abs/2508.03342)

- 2. Deason et al., CyberSOCEval, 2025 — arXiv:2509.20166

- 3. Freitas & Gharib, GraphWeaver: Billion-Scale Cybersecurity Incident Correlation, 2024 — arXiv:2406.01842

- 4. Freitas et al., AI-Driven Guided Response for SOCs with Microsoft Copilot for Security, 2024 — arXiv:2407.09017 [URL 🔗](https://arxiv.org/abs/2407.09017)

- 5. Habibzadeh et al., Comprehensive Survey, 2025 — arXiv:2509.10858 Large Language Models for Security Operations Centers: A

- 6. Islam, Babar, Nepal, — arXiv:2002.09190 A Multi-Vocal Review of Security Orchestration, ACM CSUR 2019 [URL 🔗](https://arxiv.org/abs/2002.09190)

- 7. Lin et al., IRCopilot: Automated Incident Response with Large Language Models, CCS 2025 — arXiv:2505.20945 [URL 🔗](https://arxiv.org/abs/2505.20945)

- 8. Pandey & Bhujang, Poisoning the Watchtower, 2026 — arXiv:2605.24421

- 9. Singh et al., LLMs in the SOC: An Empirical Study of Human-AI Collaboration, 2025 — arXiv:2508.18947 [URL 🔗](https://arxiv.org/abs/2508.18947)

- 10. Tsegai et al., From Investigation Failures to Reliable SOC Agents, 2026 — arXiv:2610.10608 [URL 🔗](https://arxiv.org/abs/2610.10608)

- 11. Wei et al., CORTEX: Collaborative LLM Agents for High-Stakes Alert Triage, 2025 — arXiv:2510.00311 [URL 🔗](https://arxiv.org/abs/2510.00311)

- 12. Wu et al., ExCyTIn-Bench: Evaluating LLM Agents on Cyber Threat Investigation, ICML 2026 — arXiv:2507.14201 [URL 🔗](https://arxiv.org/abs/2507.14201)
