import json
from collections import defaultdict
from agents.mitre_kb import MitreKnowledgeBase


class CorrelationAgent:
    """
    Agent 2 : Corrélation (Règles déterministes + Enrichissement ATT&CK - Niveau L4).
    Agrège les événements normalisés de l'Agent Perception, détecte les séquences
    anormales et les étiquette avec leur identifiant MITRE ATT&CK.
    """

    def __init__(self, kb: MitreKnowledgeBase, ssh_bruteforce_threshold: int = 2):
        self.kb = kb
        self.ssh_bruteforce_threshold = ssh_bruteforce_threshold

    def correlate(self, normalized_events: list[dict]) -> list[dict]:
        """Regroupe les événements par (src_ip, target_host) et génère des hypothèses d'incident."""
        grouped_ssh = defaultdict(list)
        incidents = []

        for event in normalized_events:
            if event.get("event_type") == "authentication_failure":
                key = (event["src_ip"], event["target_host"])
                grouped_ssh[key].append(event)

        # Règle 1 : Détection de Brute Force SSH -> MITRE ATT&CK T1110
        for (src_ip, target_host), events in grouped_ssh.items():
            if len(events) >= self.ssh_bruteforce_threshold:
                attack_meta = self.kb.get_attack_technique("T1110")
                target_critical = any(e.get("target_critical", False) for e in events)
                # Plus il y a d'échecs, plus la confiance augmente (plafonnée à 0.99)
                confidence = min(0.75 + 0.05 * len(events), 0.99)

                incidents.append({
                    "incident_id": f"INC-SSH-{src_ip}-{target_host}",
                    "attack_id": "T1110",
                    "attack_name": attack_meta.get("name"),
                    "tactics": attack_meta.get("tactics", []),
                    "src_ip": src_ip,
                    "target_host": target_host,
                    "target_critical": target_critical,
                    "event_count": len(events),
                    "confidence": round(confidence, 2),
                    "targeted_users": sorted({e["target_user"] for e in events}),
                    "raw_context": "\n".join(e["raw_payload"] for e in events),
                })

        return incidents


if __name__ == "__main__":
    from agents.perception import PerceptionAgent

    # Simulation d'enchaînement Agent 1 (Perception) -> Agent 2 (Corrélation)
    sample_logs = [
        "Nov 15 18:10:01 web-dmz sshd[1042]: Failed password for invalid user admin from 10.40.0.15 port 51234 ssh2",
        "Nov 15 18:10:02 web-dmz sshd[1043]: Failed password for root from 10.40.0.15 port 51236 ssh2",
        "Nov 15 18:10:03 web-dmz sshd[1044]: Failed password for user from 10.40.0.15 port 51238 ssh2",
    ]

    perception = PerceptionAgent()
    events = perception.process_batch(sample_logs, source_type="ssh", target_critical=True)

    kb = MitreKnowledgeBase()
    correlation = CorrelationAgent(kb=kb, ssh_bruteforce_threshold=2)
    hypotheses = correlation.correlate(events)

    print(f"Hypothèses d'incident générées : {len(hypotheses)}")
    print(json.dumps(hypotheses, indent=2, ensure_ascii=False))