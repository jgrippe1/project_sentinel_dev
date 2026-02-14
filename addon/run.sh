#!/usr/bin/with-contenv bashio

echo "Starting Project Sentinel..."

# Export configuration for python to pick up if needed, though we use /data/options.json normally
export LOG_LEVEL=$(bashio::config 'log_level')

# Start the application
python3 -m sentinel.core
