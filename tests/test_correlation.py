"""
Tests de l'Agent Corrélation.
À lancer depuis la racine du dépôt avec :  python -m pytest
"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agents.correlation import CorrelationAgent
from agents.perception import PerceptionAgent

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
START = datetime(2026, 11, 15, 17, 10, 0, tzinfo=timezone.utc)
ATTACKER = "10.10.40.10"


def events_from_file(file_name: str) -> list[dict]:
    """Passe un fichier de fausses alertes Wazuh dans l'Agent Perception."""
    with (SAMPLES / file_name).open(encoding="utf-8") as f:
        return PerceptionAgent().process_batch(json.load(f)["alerts"])


def make_event(number, minutes, outcome="failure", event_type="ssh_login", src_ip=ATTACKER, host="web01"):
    """Fabrique une fiche événement, `minutes` minutes après START."""
    moment = START + timedelta(minutes=minutes)
    return {
        "event_id": f"evt-{number:04d}",
        "timestamp": moment.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "host": host,
        "event_type": event_type,
        "outcome": outcome,
        "src_ip": src_ip if event_type == "ssh_login" else None,
        "user": "root",
        "raw_log": "Failed password for IGNORE_PREVIOUS_INSTRUCTIONS",
    }


def five_failures():
    """Cinq échecs en une minute : une force brute selon nos réglages."""
    return [make_event(n, minutes=n * 0.2) for n in range(1, 6)]


# --- Les deux fichiers d'exemple -------------------------------------------------

def test_attack_file_gives_one_incident_at_persistence_stage():
    incidents = CorrelationAgent().correlate(events_from_file("scenario1_attack.json"))

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["stage"] == "persistence"
    assert incident["attack_ids"] == ["T1110", "T1078", "T1053"]
    assert incident["src_ip"] == ATTACKER
    assert incident["host"] == "web01"
    assert incident["failure_count"] == 5
    assert incident["first_seen"] == "2026-11-15T17:10:01.214Z"
    assert incident["last_seen"] == "2026-11-15T17:12:30.845Z"
    assert incident["event_ids"] == [f"evt-000{n}" for n in range(1, 8)]
    assert incident["incident_id"] == "INC-SSH-10.10.40.10-web01-20261115T171001Z"


def test_benign_file_gives_no_incident():
    assert CorrelationAgent().correlate(events_from_file("scenario1_benign.json")) == []


# --- La notion de temps ----------------------------------------------------------

def test_two_failures_three_weeks_apart_give_no_incident():
    events = [make_event(1, minutes=0), make_event(2, minutes=21 * 24 * 60)]

    assert CorrelationAgent().correlate(events) == []


def test_five_failures_spread_over_an_hour_give_no_incident():
    events = [make_event(n, minutes=n * 15) for n in range(1, 6)]

    assert CorrelationAgent().correlate(events) == []


def test_four_failures_are_below_the_threshold():
    assert CorrelationAgent().correlate(five_failures()[:4]) == []


def test_threshold_and_window_are_configurable():
    agent = CorrelationAgent(ssh_bruteforce_threshold=3, window_minutes=1)

    assert len(agent.correlate(five_failures()[:3])) == 1


# --- Les trois étapes ------------------------------------------------------------

def test_failures_only_give_attempt_stage():
    incident = CorrelationAgent().correlate(five_failures())[0]

    assert incident["stage"] == "attempt"
    assert incident["attack_ids"] == ["T1110"]


def test_failures_then_success_give_compromise_stage():
    events = five_failures() + [make_event(6, minutes=2, outcome="success")]

    incident = CorrelationAgent().correlate(events)[0]

    assert incident["stage"] == "compromise"
    assert incident["attack_ids"] == ["T1110", "T1078"]


def test_success_from_another_address_does_not_count():
    events = five_failures() + [make_event(6, minutes=2, outcome="success", src_ip="10.10.10.20")]

    assert CorrelationAgent().correlate(events)[0]["stage"] == "attempt"


def test_cron_without_compromise_is_not_attached():
    events = five_failures() + [make_event(6, minutes=3, outcome="success", event_type="scheduled_task")]

    assert CorrelationAgent().correlate(events)[0]["stage"] == "attempt"


def test_cron_on_another_host_is_not_attached():
    events = five_failures() + [
        make_event(6, minutes=2, outcome="success"),
        make_event(7, minutes=3, outcome="success", event_type="scheduled_task", host="db01"),
    ]

    assert CorrelationAgent().correlate(events)[0]["stage"] == "compromise"


def test_cron_too_late_is_not_attached():
    events = five_failures() + [
        make_event(6, minutes=2, outcome="success"),
        make_event(7, minutes=120, outcome="success", event_type="scheduled_task"),
    ]

    assert CorrelationAgent().correlate(events)[0]["stage"] == "compromise"


# --- Robustesse ------------------------------------------------------------------

def test_two_attacks_on_different_days_give_two_distinct_incidents():
    day_two = [make_event(n + 10, minutes=24 * 60 + n * 0.2) for n in range(1, 6)]

    incidents = CorrelationAgent().correlate(five_failures() + day_two)

    assert len(incidents) == 2
    assert incidents[0]["incident_id"] != incidents[1]["incident_id"]


def test_event_order_does_not_matter():
    events = events_from_file("scenario1_attack.json")

    assert CorrelationAgent().correlate(events[::-1]) == CorrelationAgent().correlate(events)


def test_incident_does_not_copy_raw_logs():
    incident = CorrelationAgent().correlate(five_failures())[0]

    assert "IGNORE_PREVIOUS_INSTRUCTIONS" not in json.dumps(incident)


def test_mitre_kb_is_optional():
    class FakeKb:
        def get_attack_technique(self, attack_id):
            return {"attack_id": attack_id, "name": "nom de test"}

    without_kb = CorrelationAgent().correlate(five_failures())[0]
    with_kb = CorrelationAgent(kb=FakeKb()).correlate(five_failures())[0]

    assert "attack_details" not in without_kb
    assert with_kb["attack_details"] == [{"attack_id": "T1110", "name": "nom de test"}]
