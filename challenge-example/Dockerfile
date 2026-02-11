FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

# ─── Layer 1: Install packages + ttyd web terminal ───────────────────────────
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        sudo cron nano dos2unix acl curl ca-certificates login && \
    # Install ttyd (web-based terminal, replaces SSH)
    curl -fsSL -o /usr/bin/ttyd \
        https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64 && \
    chmod +x /usr/bin/ttyd && \
    # Cleanup
    apt-get purge -y curl && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# ─── Layer 2: Create users + passwords ───────────────────────────────────────
RUN adduser --disabled-password --gecos "" shiba && \
    adduser --disabled-password --gecos "" eagle && \
    echo 'shiba:shiba' | chpasswd && \
    echo 'eagle:-daylapassw0rdkhongthecrack-heheh!@#$#@!' | chpasswd

# ─── Layer 3: Setup directories ──────────────────────────────────────────────
RUN mkdir -p /etc/s/e/c/r/e/t/ /var/radiohead/nirvana/muse/

# ─── Layer 4: Copy flag files ────────────────────────────────────────────────
COPY flag/p@rt1.txt /home/shiba/p@rt1.txt
COPY flag/s3cond_101.txt /etc/s/e/c/s3cond_101.txt
COPY flag/f1nal.txt /home/eagle/f1nal.txt

# ─── Layer 5: Copy eagle cronjob script ──────────────────────────────────────
COPY assets/eagle_cronjob.sh /usr/bin/eagle_cronjob.sh

# ─── Layer 6: Permissions, ACLs, cronjobs, decoys (single layer) ─────────────
RUN dos2unix /usr/bin/eagle_cronjob.sh && \
    # --- Flag permissions ---
    chmod 444 /home/shiba/p@rt1.txt /etc/s/e/c/s3cond_101.txt && \
    chown root:root /home/shiba/p@rt1.txt /etc/s/e/c/s3cond_101.txt && \
    chown -R root:eagle /home/eagle && \
    chmod -R 440 /home/eagle/ && \
    # --- ACLs ---
    (find / -type d -not -path "/tmp" -exec setfacl -m u:shiba:r-x {} + 2>/dev/null || true) && \
    setfacl -m u:shiba:rwx /var/radiohead/nirvana/muse && \
    (find / -type d -not -path "/tmp" -exec setfacl -m u:eagle:r-x {} + 2>/dev/null || true) && \
    setfacl -m u:eagle:rwx /var/radiohead/nirvana/muse && \
    # --- Eagle cronjob ---
    chmod 755 /usr/bin/eagle_cronjob.sh && \
    chown eagle:eagle /usr/bin/eagle_cronjob.sh && \
    echo '@reboot eagle /usr/bin/eagle_cronjob.sh &> /dev/null' > /etc/cron.d/eagle_cronjob && \
    echo '* * * * * eagle /usr/bin/eagle_cronjob.sh &> /dev/null' >> /etc/cron.d/eagle_cronjob && \
    chmod 644 /etc/cron.d/eagle_cronjob && \
    crontab -u eagle /etc/cron.d/eagle_cronjob && \
    # --- Decoy files (BUG FIX: removed trailing space after backslash) ---
    for i in $(seq 1 100); do \
        touch /var/s3cond_$i.txt /opt/s3cond_$i.txt /boot/s3cond_$i.txt \
              /root/s3cond_$i.txt /tmp/s3cond_$i.txt /usr/local/s3cond_$i.txt \
              /mnt/s3cond_$i.txt /lib/s3cond_$i.txt /srv/s3cond_$i.txt \
              /etc/s3cond_$i.txt /etc/s/s3cond_$i.txt /etc/s/e/s3cond_$i.txt \
              /etc/s/e/c/s3cond_$i.txt \
              /etc/s/e/c/r/s3cond_$i.txt /etc/s/e/c/r/e/s3cond_$i.txt \
              /etc/s/e/c/r/e/t/s3cond_$i.txt; \
    done && \
    # BUG FIX: use * glob instead of $i (which only matched last iteration=100)
    chmod 444 /var/s3cond_*.txt /opt/s3cond_*.txt /boot/s3cond_*.txt \
              /root/s3cond_*.txt /tmp/s3cond_*.txt /usr/local/s3cond_*.txt \
              /mnt/s3cond_*.txt /lib/s3cond_*.txt /srv/s3cond_*.txt \
              /etc/s3cond_*.txt /etc/s/s3cond_*.txt /etc/s/e/s3cond_*.txt \
              /etc/s/e/c/s3cond_*.txt \
              /etc/s/e/c/r/s3cond_*.txt /etc/s/e/c/r/e/s3cond_*.txt \
              /etc/s/e/c/r/e/t/s3cond_*.txt && \
    # --- Final hardening (consolidated, was 3 separate RUN layers) ---
    chmod 555 /home/shiba && \
    chmod 555 /home/eagle && \
    chmod 777 /var/radiohead/nirvana/muse/ && \
    # --- Tmp cleanup cron ---
    echo '*/2 * * * * root rm -rf /tmp/* &> /dev/null' > /etc/cron.d/clean_tmp && \
    chmod 644 /etc/cron.d/clean_tmp && \
    crontab /etc/cron.d/clean_tmp

# ─── Entrypoint ──────────────────────────────────────────────────────────────
COPY assets/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 7681

ENTRYPOINT ["/entrypoint.sh"]
