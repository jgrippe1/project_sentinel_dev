#!/usr/bin/with-contenv bashio

echo "Starting Project Sentinel..."

# Export configuration for python to pick up
export LOG_LEVEL=$(bashio::config 'log_level')
export SENTINEL_DB_PATH="/share/sentinel.db"
export PYTHONPATH=$PYTHONPATH:/app

# Start the Web API (Ingress) in the background with logging
echo "Starting Project Sentinel Dashboard on port 8099..."
gunicorn --access-logfile - --error-logfile - -w 2 -b 0.0.0.0:8099 sentinel.api:app &

# Small sleep to let Gunicorn bind
sleep 2

# Start the Core scanner
echo "Starting Project Sentinel Core..."
python3 -m sentinel.core
