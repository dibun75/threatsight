# VulnCheck token (optional)

Do not paste the token into chat, tickets, Cursor, or Git.

## Account and token creation

1. Create or sign in to a VulnCheck Community account: https://console.vulncheck.com  
2. Open the user profile → **Tokens & SSH Keys** → **Create Token**  
   Official guide: https://docs.vulncheck.com/getting-started/api-tokens  
3. Copy the token once (it is shown only at creation). Unused tokens expire after 30 days.

## Host file (Radar-compatible ownership)

Match the proven Radar pattern: operator-owned file, group `10001` (intel-worker), mode `0640`, never a symlink.

```bash
sudo install -d -m 0750 -o "$USER" -g 10001 /var/lib/threatsight/vulncheck
umask 027
# Write the token privately, then install with the required ownership/mode:
sudo install -m 0640 -o "$USER" -g 10001 /dev/stdin /var/lib/threatsight/vulncheck/token <<'EOF'
PASTE_TOKEN_ONCE_HERE
EOF
# Clear the shell history entry that contained the heredoc if needed, then clear clipboard.
stat -c '%A %U %G %s %n' /var/lib/threatsight/vulncheck/token
# Expected non-secret metadata example: -rw-r----- <you> 10001 <nonzero> /var/lib/threatsight/vulncheck/token
```

Alternative when the file owner must be the worker user: mode `0400` owned by `10001:10001`.

## Activation confirmation

After the file exists with correct metadata, reply exactly:

`VulnCheck token file installed.`

Do not send the token value, length, prefix, suffix, or hash.

## Compose mount

Set the host path only as a Compose variable (not in `.env`):

```bash
export THREATSIGHT_VULNCHECK_TOKEN_PATH=/var/lib/threatsight/vulncheck/token
```

Include `docker-compose.vulncheck.yml` when recreating `intel-worker`. The in-container path is `/run/secrets/vulncheck_token`. Base Compose remains valid with VulnCheck disabled and no mount.

Never put the token in `.env`, Compose command arguments, logs, database rows, images, API responses, or browser storage.
