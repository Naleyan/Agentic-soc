import json
from pathlib import Path
from mitreattack.stix20 import MitreAttackData


class MitreKnowledgeBase:
    """Interface locale entre MITRE ATT&CK (STIX 2.1) et MITRE D3FEND (JSON-LD)."""

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

    def _collect_d3fend_defenses(self, node_id: str, seen: set) -> list[dict]:
        """Parcourt le graphe D3FEND pour trouver les nœuds défensifs liés à node_id."""
        results = []
        node = self._d3fend_index.get(node_id)
        if not node:
            return results

        # 1. Liens directs portés par le nœud ATT&CK dans D3FEND
        for key, val in node.items():
            if not key.startswith("d3f:"):
                continue
            refs = val if isinstance(val, list) else [val]
            for ref in refs:
                target_id = ref.get("@id") if isinstance(ref, dict) else ref
                if (
                    isinstance(target_id, str)
                    and target_id.startswith("d3f:")
                    and not target_id.startswith("d3f:T")
                    and target_id not in seen
                ):
                    seen.add(target_id)
                    target_node = self._d3fend_index.get(target_id, {})
                    label = target_node.get("rdfs:label", target_id)
                    if isinstance(label, dict):
                        label = label.get("@value", target_id)
                    results.append(
                        {
                            "d3fend_id": target_id,
                            "name": label,
                            "relation": key,
                            "definition": target_node.get("d3f:definition", ""),
                        }
                    )

        # 2. Liens inverses : techniques défensives référençant node_id
        for candidate in self.d3fend_graph:
            cid = candidate.get("@id", "")
            if not cid.startswith("d3f:") or cid.startswith("d3f:T") or cid in seen:
                continue
            if f'"{node_id}"' in json.dumps(candidate):
                seen.add(cid)
                label = candidate.get("rdfs:label", cid)
                if isinstance(label, dict):
                    label = label.get("@value", cid)
                results.append(
                    {
                        "d3fend_id": cid,
                        "name": label,
                        "relation": "linked_to_attack",
                        "definition": candidate.get("d3f:definition", ""),
                    }
                )

        return results

    def get_d3fend_countermeasures(self, attack_id: str) -> list[dict]:
        """Retourne les contre-mesures défensives D3FEND pour un identifiant ATT&CK."""
        seen = set()
        countermeasures = self._collect_d3fend_defenses(f"d3f:{attack_id}", seen)

        if not countermeasures and "." in attack_id:
            parent_id = attack_id.split(".")[0]
            countermeasures = self._collect_d3fend_defenses(f"d3f:{parent_id}", seen)

        return countermeasures


if __name__ == "__main__":
    kb = MitreKnowledgeBase()
    for tid in ["T1110", "T1053", "T1021", "T1048", "T1486"]:
        info = kb.get_attack_technique(tid)
        cms = kb.get_d3fend_countermeasures(tid)
        print(f"\n=== {tid} : {info.get('name')} ({', '.join(info.get('tactics', []))}) ===")
        print(f"Contre-mesures D3FEND trouvées : {len(cms)}")
        for cm in cms[:5]:
            print(f"  - {cm['d3fend_id']} : {cm['name']}")