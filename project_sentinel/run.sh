#!/usr/bin/with-contenv bashio

echo "Starting Project Sentinel..."

# Export configuration for python to pick up
export LOG_LEVEL=$(bashio::config 'log_level')
export SENTINEL_DB_PATH="/share/sentinel.db"

# Start the application
python3 -m sentinel.core
