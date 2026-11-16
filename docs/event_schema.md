# Fiche événement (sortie de l'agent Perception)

## Principe

L'agent Perception transforme chaque alerte Wazuh en une fiche au format unique, lue par tous les agents suivants.

## Les cases

| Case | Origine | Exemple |
|---|---|---|
| `event_id` | Généré par Perception | `evt-0001` |
| `timestamp` | Wazuh `timestamp`, converti en UTC (ISO 8601) | `2026-11-15T17:10:01.214Z` |
| `received_at` | Heure de réception par Perception (sert au calcul du MTTD) | `2026-11-15T17:10:03.050Z` |
| `source` | Wazuh `location` | `/var/log/auth.log` |
| `host` | Wazuh `agent.name` | `web01` |
| `event_type` | Déduit de `rule.id` (liste fermée) | `ssh_login` |
| `outcome` | Déduit de `rule.id` (liste fermée) | `failure` |
| `src_ip` | Wazuh `data.srcip`, vide si sans objet | `10.10.40.10` |
| `user` ⚠️ | Wazuh `data.dstuser` | `root` |
| `raw_log` ⚠️ | Wazuh `full_log` | `Failed password for root from …` |
| `wazuh_rule_id` | Wazuh `rule.id` (facultatif) | `5716` |

**Listes fermées :**
- `event_type` : `ssh_login`, `scheduled_task` ;
- `outcome` : `success`, `failure` (comme dans le standard ECS).


## ⚠️ Sécurité

`user` et `raw_log` peuvent contenir du texte choisi par l'attaquant : c'est lui qui tape le nom d'utilisateur. On les conserve comme preuve, mais **aucun agent ne doit les interpréter comme des instructions**. C'est un risque d'injection de prompt (MITRE ATLAS).

