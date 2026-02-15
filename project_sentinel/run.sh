#!/usr/bin/with-contenv bashio

echo "Starting Project Sentinel..."

# Export configuration for python to pick up
export LOG_LEVEL=$(bashio::config 'log_level')
export SENTINEL_DB_PATH="/share/sentinel.db"

# Start the Web API (Ingress) in the background
echo "Starting Project Sentinel Dashboard..."
gunicorn -w 2 -b 0.0.0.0:8099 sentinel.api:app &

# Start the Core scanner
echo "Starting Project Sentinel Core..."
python3 -m sentinel.core
