#!/usr/bin/env python3
# generate_corpus_from_templates.py
import json
from pathlib import Path
import random
import faiss
import numpy
import requests
import torch
import transformers

OUT = Path("prepared/corpus_passages.json")
OUT.parent.mkdir(parents=True, exist_ok=True)

labels = {
    "credential_stuffing": [
        "Plusieurs tentatives de connexion échouées provenant de différentes IP sur une courte période. Souvent sur le même compte.",
        "Échecs rapides sur le même identifiant avec IP variées — pattern typique de credential stuffing."
    ],
    "brute_force": [
        "Tentatives très rapides et répétées sur un même compte depuis la même IP ou plage IP — brute-force.",
        "Nombre important d'essais mot de passe successifs sur un compte, sans variation IP notable."
    ],
    "phishing_attempt": [
        "Connexion depuis un domaine ou une IP suspecte souvent corrélée à un message de phishing.",
        "Comportement inhabituel après réception d'un email frauduleux : login depuis nouveau device."
    ],
    "session_hijack": [
        "Changement brusque de device ou IP immédiatement après une authentification réussie — possible détournement de session.",
        "Connexion depuis une géolocalisation inattendue après un login réussit; pattern divergence du profil normal."
    ],
    "malware_activity": [
        "Actions inhabituelles sur le compte (ex: exécution de scripts, accès à ressources multiples) pouvant indiquer la présence d'un malware.",
        "Accès automatique et répété à des ressources depuis un device particulier — suspicion d'activité malveillante."
    ],
    "insider_threat": [
        "Accès ou modifications de ressources sensibles par un utilisateur interne en dehors de son rôle habituel.",
        "Téléchargements massifs ou accès hors horaire d'un compte interne — comportement anormal."
    ],
    "normal": [
        "Login réussi depuis un device connu; comportements cohérents avec l'historique utilisateur.",
        "Échec isolé de mot de passe puis succès depuis le même device — comportement normal."
    ]
}

# generate multiple paraphrases per label
passages = []
pid = 1
for label, templates in labels.items():
    for i in range(12):  # generate 12 passages per label
        text = random.choice(templates)
        # slight variation
        variant = text
        if i % 2 == 0:
            variant = variant + " Indices : fréquence, IP, device."
        passages.append({
            "passage_id": f"{label}_p{str(i+1).zfill(2)}",
            "doc_id": f"{label}_doc",
            "content": variant,
            "tags": [label]
        })
        pid += 1

with open(OUT, "w", encoding="utf-8") as fh:
    json.dump(passages, fh, ensure_ascii=False, indent=2)
print("Wrote corpus passages:", OUT, "count:", len(passages))
