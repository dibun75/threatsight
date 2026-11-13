# Encrypted backup

The host backup today is a local `pg_dump` custom-format file. It does not survive loss of the disk. Off-host copy is not active.

`scripts/encrypted_backup.py` encrypts an existing custom-format dump with AES-256-GCM from the pinned `cryptography` package. No new backup tool is added to the application images. The script refuses to write the ciphertext into the same directory as the key, refuses to overwrite, and does not delete older files. `retention-preview` only prints names. `dry-run` writes nothing.

Manifest fields: time, database revision, application release, destination identifier, method, plaintext and ciphertext checksums, and sizes. The manifest does not contain the key or a connection string.

Key custody is undecided. Generate 32 random bytes and store them apart from the ciphertext. A drill key is disposable and must be deleted after the drill. Do not treat a local drill as off-host protection.

Scheduled operation, after a destination is chosen, is a host timer that runs `pg_dump -Fc` to a temporary file, then this script, then removes the plaintext. The timer is not installed. Supported destination patterns are S3-compatible storage, Azure Blob, a mounted encrypted volume, or another destination the sponsor names. Nothing is uploaded until that choice is recorded in the activation checklist.

Restore decrypts to a new file and checks both checksums. Load that file with `pg_restore` into a disposable database. Do not restore over the preserved `threatsight` database without a fresh validated backup and an explicit decision.
