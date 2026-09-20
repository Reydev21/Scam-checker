"""One-time migration of the legacy JSON files into Supabase."""

import json
import os

import app


def read_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


if __name__ == "__main__":
    users = read_json(app.USERS_FILE, {})
    logs = read_json(app.AUDIT_LOGS_FILE, [])
    blocked_ips = read_json(app.BLOCKED_IPS_FILE, [])
    app.save_users(users)
    app.save_audit_logs(logs)
    app.save_blocked_ips(blocked_ips)
    print(f"Migrated {len(users)} users, {len(logs)} audit logs, and {len(blocked_ips)} blocked IPs.")
