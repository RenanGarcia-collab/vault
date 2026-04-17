#!/usr/bin/env bash

SLEEP_SECONDS="${SCHEDULER_SLEEP_SECONDS:-60}"

while true; do
  python manage.py run-due || echo "Scheduler erro em $(date -Iseconds)"
  sleep "${SLEEP_SECONDS}"
done
