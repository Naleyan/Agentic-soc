import json
from pathlib import Path
from mitreattack.stix20 import MitreAttackData


class MitreKnowledgeBase:
    """Passerelle locale entre MITRE ATT&CK (STIX 2.1) et MITRE D3FEND (JSON-LD)."""

    # Mappage entre les motifs/tactiques D3FEND et les 5 capacités fermées du projet
    CAPABILITY_RULES = {
        "quarantaine": [
            "Isolation", "Quarantine", "Locking", "Termination", "Eviction", "Block"
        ],
        "reconfiguration_filtrante": [
            "Filtering", "Firewall", "AccessControl", "Authentication", "Hardening", "Encryption"
        ],
        "patching": [
            "Update", "Patch", "ConfigurationManagement", "Upgrade"
        ],
        "instrumentation": [
            "PacketCapture", "TrafficAnalysis", "Monitoring", "Inspection", "Tracing", "Logging"
        ],
    }

    def __init__(
        self,
        attack_path: str = "data/mitre/enterprise-attack.json",
        d3fend_path: str = "data/mitre/d3fend.json",
    ):
        self.attack_path = Path(attack_path)
        self.d3fend_path = Path(d3fend_path)

        if not self.attack_path.exists() or not self.d3fend_path.exists():
            raise FileNotFoundError(
                "Fichiers MITRE introuvables. Exécutez ./data/download_mitre.sh d'abord."
            )

        self.attack_data = MitreAttackData(str(self.attack_path))
        with self.d3fend_path.open("r", encoding="utf-8") as f:
            self.d3fend_graph = json.load(f).get("@graph", [])

        self._d3fend_index = {
            node["@id"]: node for node in self.d3fend_graph if "@id" in node
        }
        self._defensive_ids = self._index_defensive_techniques()

    def _index_defensive_techniques(self) -> set[str]:
        """Identifie tous les nœuds D3FEND appartenant à l'arbre DefensiveTechnique."""
        defensive = set()
        # Remonte la hiérarchie rdfs:subClassOf depuis d3f:DefensiveTechnique
        parents = {"d3f:DefensiveTechnique"}
        changed = True
        while changed:
            changed = False
            for node in self.d3fend_graph:
                nid = node.get("@id", "")
                if not nid.startswith("d3f:") or nid in defensive:
                    continue
                sub_of = node.get("rdfs:subClassOf", [])
                if not isinstance(sub_of, list):
                    sub_of = [sub_of]
                parent_ids = {
                    p.get("@id") if isinstance(p, dict) else p for p in sub_of
                }
                if parent_ids & (parents | defensive):
                    defensive.add(nid)
                    changed = True
        return defensive

    def _get_label(self, node_id: str) -> str:
        node = self._d3fend_index.get(node_id, {})
        label = node.get("rdfs:label", node_id)
        if isinstance(label, dict):
            return label.get("@value", node_id)
        return label

    def _extract_refs(self, node: dict) -> list[str]:
        """Extrait toutes les références d3f:... contenues dans les propriétés d'un nœud."""
        refs = []
        for key, val in node.items():
            if not key.startswith("d3f:"):
                continue
            items = val if isinstance(val, list) else [val]
            for item in items:
                target = item.get("@id") if isinstance(item, dict) else item
                if isinstance(target, str) and target.startswith("d3f:"):
                    refs.append(target)
        return refs

    def get_attack_technique(self, attack_id: str) -> dict:
        """Retourne les métadonnées ATT&CK d'une technique (ex: 'T1110')."""
        tech = self.attack_data.get_object_by_attack_id(attack_id, "attack-pattern")
        if not tech:
            return {"error": f"Technique {attack_id} introuvable dans ATT&CK"}

        tactics = [
            phase["phase_name"]
            for phase in tech.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        return {
            "attack_id": attack_id,
            "name": tech.get("name"),
            "tactics": tactics,
            "description": tech.get("description", "").split("\n")[0],
        }

    def get_d3fend_countermeasures(self, attack_id: str) -> list[dict]:
        """
        Traversée à 2 sauts dans le graphe D3FEND :
        1. Saut direct : Technique ATT&CK <-> Technique défensive D3FEND
        2. Saut indirect : Technique ATT&CK -> Artefact numérique -> Technique défensive D3FEND
        """
        target_attack = f"d3f:{attack_id}"
        found_defenses: dict[str, str] = {}  # {d3fend_id: via_relation}
        intermediate_artifacts: set[str] = set()

        # Étape 1 : inspecter le nœud ATT&CK et les nœuds qui le référencent
        attack_node = self._d3fend_index.get(target_attack)
        if attack_node:
            for ref in self._extract_refs(attack_node):
                if ref in self._defensive_ids:
                    found_defenses[ref] = "direct"
                elif not ref.startswith("d3f:T"):
                    intermediate_artifacts.add(ref)

        for node in self.d3fend_graph:
            nid = node.get("@id", "")
            if not nid.startswith("d3f:") or nid == target_attack or nid.startswith("d3f:T"):
                continue
            if target_attack in self._extract_refs(node):
                if nid in self._defensive_ids:
                    found_defenses[nid] = "direct"
                else:
                    intermediate_artifacts.add(nid)

        # Étape 2 : si des artefacts sont touchés (ex: d3f:File, d3f:InternetNetworkTraffic),
        # rechercher les techniques défensives qui protègent ou analysent ces artefacts
        if intermediate_artifacts:
            for def_id in self._defensive_ids:
                if def_id in found_defenses:
                    continue
                def_node = self._d3fend_index.get(def_id, {})
                def_refs = set(self._extract_refs(def_node))
                shared = def_refs & intermediate_artifacts
                if shared:
                    via = ", ".join(self._get_label(a) for a in sorted(shared))
                    found_defenses[def_id] = f"via artefact ({via})"

        results = []
        for def_id, relation in sorted(found_defenses.items()):
            node = self._d3fend_index.get(def_id, {})
            results.append(
                {
                    "d3fend_id": def_id,
                    "name": self._get_label(def_id),
                    "relation": relation,
                    "definition": node.get("d3f:definition", ""),
                }
            )
        return results

    def map_to_project_capabilities(self, countermeasures: list[dict]) -> dict[str, list[str]]:
        """
        Traduit les contre-mesures D3FEND vers les 5 capacités fermées de l'Agent Décision :
        alerting, quarantaine, reconfiguration_filtrante, patching, instrumentation.
        """
        mapped = {
            "alerting": ["Notification contextualisée systématique vers l'opérateur"],
            "quarantaine": [],
            "reconfiguration_filtrante": [],
            "patching": [],
            "instrumentation": [],
        }

        for cm in countermeasures:
            cid = cm["d3fend_id"]
            label = cm["name"]
            entry = f"{cid} ({label})"
            for cap, keywords in self.CAPABILITY_RULES.items():
                if any(kw.lower() in cid.lower() or kw.lower() in label.lower() for kw in keywords):
                    if entry not in mapped[cap]:
                        mapped[cap].append(entry)

        return mapped

    def analyze_attack(self, attack_id: str) -> dict:
        """Point d'entrée complet prêt à être appelé par l'Agent Corrélation / Décision."""
        attack_info = self.get_attack_technique(attack_id)
        if "error" in attack_info:
            return attack_info

        cms = self.get_d3fend_countermeasures(attack_id)
        capabilities = self.map_to_project_capabilities(cms)

        return {
            "attack": attack_info,
            "d3fend_count": len(cms),
            "d3fend_countermeasures": cms[:10],
            "recommended_capabilities": capabilities,
        }


if __name__ == "__main__":
    kb = MitreKnowledgeBase()
    # Test sur toutes les techniques des 4 scénarios du rapport
    for tid in ["T1110", "T1053", "T1021", "T1048", "T1486"]:
        res = kb.analyze_attack(tid)
        atk = res["attack"]
        print(f"\n==================== {tid} : {atk['name']} ====================")
        print(f"Tactiques : {', '.join(atk['tactics'])}")
        print(f"Contre-mesures D3FEND identifiées : {res['d3fend_count']}")
        for cm in res["d3fend_countermeasures"][:4]:
            print(f"  * {cm['d3fend_id']} : {cm['name']} [{cm['relation']}]")
        print("Capacités de réaction du projet activables :")
        for cap, items in res["recommended_capabilities"].items():
            if items:
                print(f"  -> {cap} : {', '.join(items[:3])}")