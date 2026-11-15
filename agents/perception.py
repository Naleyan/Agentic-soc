import json
import re
from datetime import datetime
from typing import Optional


class PerceptionAgent:
    """
    Agent 1 : Perception (Déterministe - Niveau L4).
    Collecte et normalise les événements bruts (logs SSH, alertes Suricata)
    vers un schéma JSON unique exploitable par l'Agent Corrélation.
    """

    # Motif regex pour les échecs de connexion SSH (auth.log)
    SSH_FAILED_PATTERN = re.compile(
        r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+"
        r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
        r"Failed password for (?:invalid user )?(?P<user>\S+)\s+"
        r"from (?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<src_port>\d+)"
    )

    def normalize_ssh_log(self, raw_line: str, target_critical: bool = False) -> Optional[dict]:
        """Parse une ligne brute de /var/log/auth.log et retourne un événement normalisé."""
        match = self.SSH_FAILED_PATTERN.search(raw_line.strip())
        if not match:
            return None

        data = match.groupdict()
        return {
            "event_type": "authentication_failure",
            "source_sensor": "linux_sshd",
            "timestamp": data["timestamp"],
            "src_ip": data["src_ip"],
            "src_port": int(data["src_port"]),
            "target_host": data["host"],
            "target_user": data["user"],
            "target_critical": target_critical,
            "raw_payload": raw_line.strip(),
        }

    def normalize_suricata_eve(self, eve_json_line: str, target_critical: bool = False) -> Optional[dict]:
        """Parse une ligne JSON Suricata (eve.json) de type 'alert'."""
        try:
            record = json.loads(eve_json_line)
        except json.JSONDecodeError:
            return None

        if record.get("event_type") != "alert":
            return None

        alert = record.get("alert", {})
        return {
            "event_type": "ids_alert",
            "source_sensor": "suricata",
            "timestamp": record.get("timestamp", datetime.utcnow().isoformat()),
            "src_ip": record.get("src_ip"),
            "src_port": record.get("src_port"),
            "dest_ip": record.get("dest_ip"),
            "dest_port": record.get("dest_port"),
            "signature": alert.get("signature", "Unknown Alert"),
            "severity": alert.get("severity", 3),
            "target_critical": target_critical,
            "raw_payload": alert.get("signature", ""),
        }

    def process_batch(self, raw_lines: list[str], source_type: str = "ssh", target_critical: bool = False) -> list[dict]:
        """Normalise un lot de lignes brutes en ignorant le bruit non pertinent."""
        normalized_events = []
        for line in raw_lines:
            if source_type == "ssh":
                event = self.normalize_ssh_log(line, target_critical=target_critical)
            elif source_type == "suricata":
                event = self.normalize_suricata_eve(line, target_critical=target_critical)
            else:
                raise ValueError(f"Type de source non supporté : {source_type}")

            if event:
                normalized_events.append(event)

        return normalized_events


if __name__ == "__main__":
    agent = PerceptionAgent()

    sample_ssh_logs = [
        "Nov 15 18:10:01 web-dmz sshd[1042]: Failed password for invalid user admin from 10.40.0.15 port 51234 ssh2",
        "Nov 15 18:10:02 web-dmz sshd[1043]: Failed password for root from 10.40.0.15 port 51236 ssh2",
        "Nov 15 18:10:05 web-dmz CRON[1050]: (root) CMD (command -v debian-sa1 > /dev/null)",
    ]

    events = agent.process_batch(sample_ssh_logs, source_type="ssh", target_critical=True)
    print(f"Événements retenus : {len(events)} / {len(sample_ssh_logs)}")
    print(json.dumps(events, indent=2, ensure_ascii=False))