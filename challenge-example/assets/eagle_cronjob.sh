#!/bin/bash
# Eagle's cronjob - runs every minute as user eagle
# Checks the shared directory for requests from shiba

SHARED_DIR="/var/radiohead/nirvana/muse"
FLAG_FILE="/home/eagle/f1nal.txt"

# If shiba leaves a file named "request.txt" in the shared dir,
# eagle copies the final flag there
if [ -f "$SHARED_DIR/request.txt" ]; then
    cp "$FLAG_FILE" "$SHARED_DIR/response.txt" 2>/dev/null
    chmod 444 "$SHARED_DIR/response.txt" 2>/dev/null
    rm -f "$SHARED_DIR/request.txt"
fi
