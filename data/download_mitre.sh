#!/usr/bin/env bash
set -e
mkdir -p data/mitre
curl -L -o data/mitre/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
curl -L -o data/mitre/d3fend.json \
  https://d3fend.mitre.org/ontologies/d3fend.json
