import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from apscheduler.schedulers.blocking import BlockingScheduler
from elasticsearch import Elasticsearch, exceptions as es_exceptions
from pymongo import MongoClient, errors as mongo_errors

from SMET import map_attack_vector

# ─────────────────────────────────────
# 1.  Configuration constants
# ─────────────────────────────────────
MONGO_URI  = "xxxxxxxxxxxxxxxx"
DB_NAME    = "Cybercarders"
COLL_NAME  = "honey_mitre_rule"

STIX_PATH  = Path("enterprise-attack.json")

ES_CLOUD_ID = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
ES_USER     = "elastic"
ES_PASS     = "xxxxxxxxxxxxxxxxxxx"
ES_INDEX    = "honeypot_ip_test"

LOG_PATH    = "mapping_job.log"

TACTIC_NAME_TO_ID = {
    'reconnaissance': 'TA0043',
    'resource-development': 'TA0042',
    'initial-access': 'TA0001',
    'execution': 'TA0002',
    'persistence': 'TA0003',
    'privilege-escalation': 'TA0004',
    'defense-evasion': 'TA0005',
    'credential-access': 'TA0006',
    'discovery': 'TA0007',
    'lateral-movement': 'TA0008',
    'collection': 'TA0009',
    'command-and-control': 'TA0011',
    'exfiltration': 'TA0010',
    'impact': 'TA0040',
}

# ─────────────────────────────────────
# 2.  Logging setup
# ─────────────────────────────────────
logger = logging.getLogger("mitre_mapper")
logger.setLevel(logging.INFO)

fmt = logging.Formatter(
    "%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

console = logging.StreamHandler()
console.setFormatter(fmt)
logger.addHandler(console)

file_handler = RotatingFileHandler(LOG_PATH, maxBytes=5_000_000, backupCount=5)
file_handler.setFormatter(fmt)
logger.addHandler(file_handler)

# ─────────────────────────────────────
# 3.  One‑time initialisation
# ─────────────────────────────────────
try:
    logger.info("Loading ATT&CK STIX bundle …")
    with STIX_PATH.open() as fh:
        stix_bundle = json.load(fh)

    technique_to_tactics: dict[str, list[str]] = defaultdict(list)
    for obj in stix_bundle["objects"]:
        if obj.get("type") == "attack-pattern":
            tid = obj["external_references"][0]["external_id"]
            phases = [p["phase_name"] for p in obj.get("kill_chain_phases", [])]
            technique_to_tactics[tid] = phases if phases else ['no tactics found']
    logger.info("Loaded %s techniques from STIX", len(technique_to_tactics))
except Exception as e:
    logger.exception("Failed during STIX initialisation – aborting.")
    raise SystemExit(1)

# Mongo & Elasticsearch clients are created once and reused
mongo_client = MongoClient(MONGO_URI)
coll = mongo_client[DB_NAME][COLL_NAME]

es = Elasticsearch(
    cloud_id=ES_CLOUD_ID,
    basic_auth=(ES_USER, ES_PASS),
    request_timeout=600
)

# ─────────────────────────────────────
# 4.  Mapping job implementation
# ─────────────────────────────────────
def run_mapping_job() -> None:
    run_start = datetime.utcnow()
    logger.info("— Job started —")
    try:
        query = {
            "size": 0,
            "query": {"range": {"data._source.@timestamp": {"gte": "now-24h"}}},
            "aggs": {
                "sig": {
                    "terms": {
                        "field": "data._source.suricata.eve.alert.signature.keyword",
                        "size": 10_000
                    }
                }
            }
        }

        try:
            res = es.search(index=ES_INDEX, body=query)
        except es_exceptions.ElasticsearchException as e:
            logger.error("Elasticsearch query failed: %s", e)
            return

        buckets = res["aggregations"]["sig"]["buckets"]
        logger.info("%d unique signatures found in the last 24h", len(buckets))

        inserted = skipped = 0
        for bucket in buckets:
            signature = bucket["key"]

            try:
                if coll.find_one({"signature_msg": signature}):
                    skipped += 1
                    continue
            except mongo_errors.PyMongoError as e:
                logger.error("Mongo read error: %s", e)
                return  # stop run; don't risk duplicate inserts

            # Technique selection (score ≥ 0.1 else fallback top‑2)
            raw_matches = map_attack_vector(signature)          # → [(tech_id, score), …]
            techniques = [tid for tid, score in raw_matches if score >= 0.1] \
                         or [tid for tid, _ in raw_matches[:2]] \
                         or ["No Technique"]

            # Tactic lookup
            tactic_ids = set()
            for tech in techniques:
                for tname in technique_to_tactics.get(tech, ['no tactics found']):
                    t_id = TACTIC_NAME_TO_ID.get(tname.lower())
                    if t_id:
                        tactic_ids.add(t_id)
            tactic_ids = sorted(tactic_ids) or ["No Tactic"]

            doc = {
                "signature_msg":  signature,
                "mitre_technique": ", ".join(techniques),
                "mitre_tactic":   ", ".join(tactic_ids),
                "description":    "Mapped using SMET",
                "created_at":     datetime.utcnow(),
            }

            try:
                coll.insert_one(doc)
                inserted += 1
            except mongo_errors.PyMongoError as e:
                logger.error("Mongo insert failed for %s: %s", signature, e)

        logger.info("Job complete – %d inserted, %d skipped", inserted, skipped)
    except Exception:
        logger.exception("Unexpected error in mapping job")
    finally:
        duration = (datetime.utcnow() - run_start).total_seconds()
        logger.info("— Job finished in %.1f s —", duration)

# ─────────────────────────────────────
# 5.  Scheduler (daily)
# ─────────────────────────────────────
scheduler = BlockingScheduler(timezone="UTC")
# runs every day at 00:00 UTC; tweak hour/minute if desired
scheduler.add_job(run_mapping_job, trigger='cron', hour=0, minute=0,
                  id='daily_mitre_mapping')

try:
    logger.info("Scheduler started – next run at %s", scheduler.get_jobs()[0].next_run_time)
    scheduler.start()
except (KeyboardInterrupt, SystemExit):
    logger.info("Scheduler stopped by user; exiting…")
