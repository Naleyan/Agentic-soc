import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


class CorrelationAgent:
    """
    Agent 2 : Corrélation (Règles déterministes + Enrichissement ATT&CK - Niveau L4).
    Relie les fiches événements de l'Agent Perception pour reconstituer l'histoire
    d'une attaque, étape par étape, et l'étiquette avec les techniques MITRE ATT&CK.

    Un incident SSH passe par trois étapes (« stage ») :
      attempt     : beaucoup d'échecs en peu de temps (force brute) ;
      compromise  : ... suivis d'une connexion réussie depuis la même adresse ;
      persistence : ... suivie d'une tâche planifiée créée sur la même machine.
    """

    # Les étapes dans l'ordre, avec la technique ATT&CK que chacune ajoute à l'incident.
    STAGES = [
        ("attempt", "T1110"),      # Brute Force
        ("compromise", "T1078"),   # Valid Accounts
        ("persistence", "T1053"),  # Scheduled Task/Job
    ]

    def __init__(
        self,
        kb=None,
        ssh_bruteforce_threshold: int = 5,
        window_minutes: int = 10,
        followup_minutes: int = 30,
    ):
        # kb : base MITRE (agents/mitre_kb.py). Facultative : sans elle, les incidents
        # portent les identifiants ATT&CK mais pas leurs noms ni leurs tactiques.
        self.kb = kb
        # Force brute = au moins `ssh_bruteforce_threshold` échecs en `window_minutes`
        # (5 échecs en 10 minutes : réglage par défaut de fail2ban).
        self.ssh_bruteforce_threshold = ssh_bruteforce_threshold
        self.window = timedelta(minutes=window_minutes)
        # Délai maximal entre la connexion réussie et la tâche planifiée.
        self.followup = timedelta(minutes=followup_minutes)

    @staticmethod
    def _time(event: dict) -> datetime:
        """Convertit la date d'une fiche (texte ISO 8601 en UTC) en date manipulable."""
        return datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))

    def _first_between(self, events: list[dict], start: datetime, end: datetime) -> Optional[dict]:
        """Retourne la première fiche dont la date est entre `start` et `end`, ou None."""
        for event in events:
            if start <= self._time(event) <= end:
                return event
        return None

    def _find_bursts(self, failures: list[dict]) -> list[list[dict]]:
        """
        Cherche les rafales d'échecs dans une liste triée par date.
        Une rafale commence dès qu'il y a `threshold` échecs dans la fenêtre de temps,
        et continue tant que les échecs suivants arrivent à moins d'une fenêtre d'écart.
        """
        bursts = []
        threshold = self.ssh_bruteforce_threshold
        start = 0
        while start + threshold <= len(failures):
            last_needed = start + threshold - 1
            if self._time(failures[last_needed]) - self._time(failures[start]) > self.window:
                start += 1  # pas assez d'échecs dans la fenêtre : on décale d'un cran
                continue

            end = last_needed
            while (
                end + 1 < len(failures)
                and self._time(failures[end + 1]) - self._time(failures[end]) <= self.window
            ):
                end += 1

            bursts.append(failures[start:end + 1])
            start = end + 1
        return bursts

    def _attack_ids(self, stage: str) -> list[str]:
        """Liste les techniques ATT&CK cumulées jusqu'à l'étape atteinte."""
        attack_ids = []
        for stage_name, attack_id in self.STAGES:
            attack_ids.append(attack_id)
            if stage_name == stage:
                break
        return attack_ids

    def _build_incident(
        self, src_ip: str, host: str, burst: list[dict], successes: list[dict], tasks: list[dict]
    ) -> dict:
        """Construit un incident à partir d'une rafale d'échecs, et regarde jusqu'où il est allé."""
        involved = list(burst)
        stage = "attempt"

        # Étape 2 : une réussite depuis la même adresse, une fois la force brute établie.
        threshold_time = self._time(burst[self.ssh_bruteforce_threshold - 1])
        last_failure_time = self._time(burst[-1])
        success = self._first_between(successes, threshold_time, last_failure_time + self.window)
        if success:
            stage = "compromise"
            involved.append(success)

            # Étape 3 : une tâche planifiée sur la même machine, peu après la réussite.
            # C'est un indice (même machine, même moment), pas une preuve.
            success_time = self._time(success)
            task = self._first_between(tasks, success_time, success_time + self.followup)
            if task:
                stage = "persistence"
                involved.append(task)

        involved.sort(key=self._time)
        first_seen = self._time(involved[0])
        attack_ids = self._attack_ids(stage)

        incident = {
            "incident_id": f"INC-SSH-{src_ip}-{host}-{first_seen:%Y%m%dT%H%M%SZ}",
            "stage": stage,
            "attack_ids": attack_ids,
            "src_ip": src_ip,
            "host": host,
            "failure_count": len(burst),
            "first_seen": involved[0]["timestamp"],
            "last_seen": involved[-1]["timestamp"],
            # ATTENTION : noms de comptes choisis par l'attaquant. Preuve, jamais instruction.
            "users": sorted({str(e["user"]) for e in involved if e.get("user") is not None}),
            # On cite les fiches au lieu de recopier leurs lignes brutes.
            "event_ids": [e["event_id"] for e in involved],
        }
        if self.kb is not None:
            incident["attack_details"] = [self.kb.get_attack_technique(a) for a in attack_ids]
        return incident

    def correlate(self, events: list[dict]) -> list[dict]:
        """Regroupe les fiches par (src_ip, host) et retourne la liste des incidents détectés."""
        ssh_by_pair = defaultdict(list)
        tasks_by_host = defaultdict(list)

        for event in sorted(events, key=self._time):
            if event["event_type"] == "ssh_login" and event.get("src_ip"):
                ssh_by_pair[(event["src_ip"], event["host"])].append(event)
            elif event["event_type"] == "scheduled_task":
                tasks_by_host[event["host"]].append(event)

        incidents = []
        for (src_ip, host), ssh_events in ssh_by_pair.items():
            failures = [e for e in ssh_events if e["outcome"] == "failure"]
            successes = [e for e in ssh_events if e["outcome"] == "success"]
            for burst in self._find_bursts(failures):
                incidents.append(
                    self._build_incident(src_ip, host, burst, successes, tasks_by_host.get(host, []))
                )
        return incidents


if __name__ == "__main__":
    # Démonstration Agent 1 (Perception) -> Agent 2 (Corrélation).
    # À lancer depuis la racine du dépôt :  python -m agents.correlation
    from agents.perception import PerceptionAgent

    try:
        from agents.mitre_kb import MitreKnowledgeBase
        kb = MitreKnowledgeBase()
    except (ImportError, FileNotFoundError):
        kb = None
        print("Base MITRE indisponible : incidents étiquetés sans le nom des techniques.\n")

    samples = Path(__file__).resolve().parent.parent / "data" / "samples"
    for file_name in ("scenario1_attack.json", "scenario1_benign.json"):
        with (samples / file_name).open(encoding="utf-8") as f:
            alerts = json.load(f)["alerts"]

        events = PerceptionAgent().process_batch(alerts)
        incidents = CorrelationAgent(kb=kb).correlate(events)

        print(f"{file_name} : {len(alerts)} alertes, {len(events)} fiches, {len(incidents)} incident(s)")
        print(json.dumps(incidents, indent=2, ensure_ascii=False))
