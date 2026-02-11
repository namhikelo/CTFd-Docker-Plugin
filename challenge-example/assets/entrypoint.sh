#!/bin/bash
# Start cron daemon (for eagle_cronjob + tmp cleanup)
cron

# Start ttyd web terminal on port 7681
# - Auto-login as shiba (credentials given in challenge description)
# - Players can `su eagle` if they find eagle's password
# - --max-clients 2: limit concurrent connections per container
exec ttyd -p 7681 --writable --max-clients 2 su -l shiba
