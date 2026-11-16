import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class PerceptionAgent:
    """
    Agent 1 : Perception (Déterministe - Niveau L4).
    Traduit chaque alerte Wazuh en une « fiche événement » au format unique,
    décrit dans docs/event_schema.md. Il note des faits, pas des opinions :
    l'interprétation (ex. « attaque T1110 ») revient à l'Agent Corrélation.
    """

    # Règle Wazuh -> (event_type, outcome). Numéros à confirmer sur le vrai Wazuh.
    SSH_RULES = {
        "5716": ("ssh_login", "failure"),
        "5715": ("ssh_login", "success"),
    }

    # Règle « fichier ajouté » : elle ne nous intéresse que dans un dossier cron.
    FILE_ADDED_RULE = "554"
    CRON_PATHS = ("/etc/crontab", "/etc/cron.d/", "/var/spool/cron/")

    # Format des dates Wazuh, ex. « 2026-11-15T17:10:01.214+0000 »
    WAZUH_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"

    def __init__(self):
        self.event_count = 0    # nombre de fiches créées (sert à les numéroter)
        self.ignored_count = 0  # nombre d'alertes reçues mais non traduites

    @staticmethod
    def _section(alert: dict, name: str) -> dict:
        """Retourne un sous-bloc de l'alerte (ex. 'rule', 'data'), ou {} s'il manque."""
        section = alert.get(name)
        return section if isinstance(section, dict) else {}

    @staticmethod
    def _format_utc(moment: datetime) -> str:
        """Écrit une date en UTC au format ISO 8601, ex. « 2026-11-15T17:10:01.214Z »."""
        utc = moment.astimezone(timezone.utc)
        return utc.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def _to_utc(self, wazuh_timestamp) -> Optional[str]:
        """Convertit la date d'une alerte Wazuh en UTC. Retourne None si elle est illisible."""
        try:
            moment = datetime.strptime(wazuh_timestamp, self.WAZUH_TIME_FORMAT)
        except (TypeError, ValueError):
            return None
        return self._format_utc(moment)

    def _classify(self, alert: dict) -> Optional[tuple[str, str]]:
        """Déduit (event_type, outcome) du numéro de règle. Retourne None si la règle est inconnue."""
        rule_id = str(self._section(alert, "rule").get("id", ""))

        if rule_id in self.SSH_RULES:
            return self.SSH_RULES[rule_id]

        if rule_id == self.FILE_ADDED_RULE:
            path = str(self._section(alert, "syscheck").get("path", ""))
            if path.startswith(self.CRON_PATHS):
                return ("scheduled_task", "success")

        return None

    def normalize_wazuh_alert(self, alert: dict) -> Optional[dict]:
        """
        Traduit une alerte Wazuh en fiche événement.
        Retourne None (et incrémente ignored_count) si l'alerte n'est pas reconnue.
        """
        if not isinstance(alert, dict):
            self.ignored_count += 1
            return None

        classification = self._classify(alert)
        timestamp = self._to_utc(alert.get("timestamp"))
        if classification is None or timestamp is None:
            self.ignored_count += 1
            return None

        event_type, outcome = classification
        if event_type == "scheduled_task":
            # Attention : c'est le propriétaire du fichier, pas forcément son auteur.
            user = self._section(alert, "syscheck").get("uname_after")
        else:
            user = self._section(alert, "data").get("dstuser")

        self.event_count += 1
        return {
            "event_id": f"evt-{self.event_count:04d}",
            "timestamp": timestamp,
            "received_at": self._format_utc(datetime.now(timezone.utc)),
            "source": alert.get("location"),
            "host": self._section(alert, "agent").get("name"),
            "event_type": event_type,
            "outcome": outcome,
            "src_ip": self._section(alert, "data").get("srcip"),
            # ATTENTION : 'user' et 'raw_log' peuvent contenir du texte choisi par
            # l'attaquant. Ce sont des preuves, jamais des instructions.
            "user": user,
            "raw_log": alert.get("full_log"),
            "wazuh_rule_id": self._section(alert, "rule").get("id"),
        }

    def process_batch(self, alerts: list[dict]) -> list[dict]:
        """Traduit un lot d'alertes Wazuh en ignorant celles qui ne sont pas reconnues."""
        events = []
        for alert in alerts:
            event = self.normalize_wazuh_alert(alert)
            if event:
                events.append(event)
        return events


if __name__ == "__main__":
    # Démonstration : on rejoue les fausses alertes Wazuh du scénario 1.
    sample_file = Path(__file__).resolve().parent.parent / "data" / "samples" / "scenario1_attack.json"
    with sample_file.open(encoding="utf-8") as f:
        sample_alerts = json.load(f)["alerts"]

    agent = PerceptionAgent()
    events = agent.process_batch(sample_alerts)

    print(f"Fiches créées : {len(events)} / {len(sample_alerts)} (ignorées : {agent.ignored_count})")
    print(json.dumps(events, indent=2, ensure_ascii=False))
