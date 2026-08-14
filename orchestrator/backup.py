"""Backup and restore of the decision store (E4, M15).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

What is worth backing up is narrow and absolute. Detections can be re-sent by
the tools that raised them and an analysis can be re-run, but a **decision, a
human correction, an outcome and a receipt exist in exactly one place** — this
database — and nothing upstream can reproduce them. That is the same reason
C4's retention deletes vendor payload copies and never a judgement.

Three properties, each from the playbook (§9):

* **Consistent while running.** SQLite's own backup API copies a live database
  correctly; ``cp`` on a file with an open write transaction copies a database
  that will not open.
* **Verified, and a mismatch raises.** The manifest carries a SHA-256 of the
  archive. Restore checks it *before* touching anything, and refuses rather
  than returning something plausible.
* **Restore never overwrites in place.** The existing database is moved aside
  with a timestamp first. A restore that turns out to be the wrong archive
  must be survivable.

Usage:

    python backup.py create  [--out data/backups]
    python backup.py verify  data/backups/ao-soc-20260814T101500.db
    python backup.py restore data/backups/ao-soc-20260814T101500.db [--yes]
    python backup.py list    [--dir data/backups]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DB_FILE = os.getenv('ORCHESTRATOR_DB_FILE') or os.getenv('DB_FILE', 'soc_matrix.db')
BACKUP_DIR = Path(os.getenv('BACKUP_DIR') or (Path('data') / 'backups'))

#: The tables whose loss is unrecoverable. Counted into every manifest, so a
#: restore can be checked against what was taken rather than only against a
#: hash of bytes nobody has read.
IRREPLACEABLE_TABLES = (
    'tier2_decisions',
    'decision_corrections',
    'decision_outcomes',
    'alert_soar_actions',
    'cases',
    'case_events',
    'situations',
    'detections',
    'security_events',
)


def _utcnow_stamp() -> str:
    return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _app_version() -> str:
    """Stamped into the manifest (playbook §9) so an archive names its build."""
    for candidate in (Path('VERSION'), Path('..') / 'VERSION', Path(__file__).parent.parent / 'VERSION'):
        try:
            return candidate.read_text(encoding='utf-8').strip()
        except OSError:
            continue
    return 'unknown'


def _counts(path: Path) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    connection = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
    try:
        for table in IRREPLACEABLE_TABLES:
            try:
                counts[table] = connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
            except sqlite3.Error:
                # A table that does not exist yet is not an error: an archive
                # from before a migration is still a valid archive.
                counts[table] = -1
    finally:
        connection.close()
    return counts


def _integrity(path: Path) -> str:
    connection = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
    try:
        return str(connection.execute('PRAGMA integrity_check').fetchone()[0])
    finally:
        connection.close()


def manifest_path(archive: Path) -> Path:
    return archive.with_suffix(archive.suffix + '.manifest.json')


# --- create ---------------------------------------------------------------


def create_backup(source: Optional[str] = None, out_dir: Optional[str] = None) -> Dict[str, Any]:
    """Take a consistent copy of the live database and describe it."""
    src = Path(source or DB_FILE)
    if not src.is_file():
        raise FileNotFoundError(f'No database at {src}')

    target_dir = Path(out_dir or BACKUP_DIR)
    target_dir.mkdir(parents=True, exist_ok=True)
    archive = target_dir / f'ao-soc-{_utcnow_stamp()}.db'

    # The backup API, not a file copy: it takes a consistent snapshot of a
    # database that is being written to, which is the only state a running SOC
    # ever offers.
    source_connection = sqlite3.connect(str(src))
    destination = sqlite3.connect(str(archive))
    try:
        with destination:
            source_connection.backup(destination)
    finally:
        destination.close()
        source_connection.close()

    integrity = _integrity(archive)
    if integrity != 'ok':
        archive.unlink(missing_ok=True)
        raise RuntimeError(f'Backup failed its integrity check: {integrity}')

    manifest = {
        'archive': archive.name,
        'source': str(src.resolve()),
        'created_at': datetime.now(timezone.utc).isoformat(),
        'app_version': _app_version(),
        'sha256': _sha256(archive),
        'bytes': archive.stat().st_size,
        'integrity': integrity,
        'rows': _counts(archive),
    }
    manifest_path(archive).write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8'
    )
    logger.info('Backup written to %s (%d bytes)', archive, manifest['bytes'])
    return manifest


# --- verify ---------------------------------------------------------------


def verify_backup(archive_path: str) -> Dict[str, Any]:
    """Is this archive the one that was taken, and does it still open?

    Checked in that order deliberately. A hash mismatch means the bytes are not
    what was recorded, and nothing further should be believed about them.
    """
    archive = Path(archive_path)
    if not archive.is_file():
        raise FileNotFoundError(f'No archive at {archive}')

    manifest_file = manifest_path(archive)
    manifest = {}
    if manifest_file.is_file():
        manifest = json.loads(manifest_file.read_text(encoding='utf-8'))

    digest = _sha256(archive)
    recorded = manifest.get('sha256')
    if recorded and digest != recorded:
        raise RuntimeError(
            f'Archive {archive.name} does not match its manifest '
            f'(sha256 {digest[:16]}… recorded {recorded[:16]}…) — refusing to trust it'
        )

    integrity = _integrity(archive)
    if integrity != 'ok':
        raise RuntimeError(f'Archive {archive.name} fails its integrity check: {integrity}')

    return {
        'archive': str(archive),
        'sha256': digest,
        'manifest': bool(manifest),
        'manifest_matches': bool(recorded) and digest == recorded,
        'integrity': integrity,
        'app_version': manifest.get('app_version'),
        'created_at': manifest.get('created_at'),
        'rows': _counts(archive),
        'rows_at_backup': manifest.get('rows'),
    }


# --- restore ---------------------------------------------------------------


def restore_backup(archive_path: str, target: Optional[str] = None) -> Dict[str, Any]:
    """Put an archive back, after verifying it and preserving what is there."""
    report = verify_backup(archive_path)
    destination = Path(target or DB_FILE)

    displaced = None
    if destination.is_file():
        displaced = destination.with_name(f'{destination.name}.replaced-{_utcnow_stamp()}')
        destination.replace(displaced)
        logger.warning('Existing database moved aside to %s', displaced)

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(Path(archive_path).read_bytes())

    restored_integrity = _integrity(destination)
    if restored_integrity != 'ok':
        raise RuntimeError(f'Restored database fails its integrity check: {restored_integrity}')

    logger.info('Restored %s to %s', archive_path, destination)
    return {
        'restored': str(destination),
        'from': archive_path,
        'previous_database': str(displaced) if displaced else None,
        'rows': report['rows'],
    }


def list_backups(directory: Optional[str] = None) -> List[Dict[str, Any]]:
    target_dir = Path(directory or BACKUP_DIR)
    if not target_dir.is_dir():
        return []
    items = []
    for archive in sorted(target_dir.glob('ao-soc-*.db'), reverse=True):
        manifest_file = manifest_path(archive)
        manifest = {}
        if manifest_file.is_file():
            try:
                manifest = json.loads(manifest_file.read_text(encoding='utf-8'))
            except (OSError, json.JSONDecodeError):
                manifest = {'error': 'manifest unreadable'}
        items.append({
            'archive': str(archive),
            'bytes': archive.stat().st_size,
            'created_at': manifest.get('created_at'),
            'app_version': manifest.get('app_version'),
            'decisions': (manifest.get('rows') or {}).get('tier2_decisions'),
        })
    return items


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level='INFO', format='%(levelname)-7s %(message)s')
    parser = argparse.ArgumentParser(description='AI-SOC decision store backup and restore')
    sub = parser.add_subparsers(dest='command', required=True)

    create = sub.add_parser('create', help='take a verified backup')
    create.add_argument('--source', default=None)
    create.add_argument('--out', default=None)

    verify = sub.add_parser('verify', help='check an archive against its manifest')
    verify.add_argument('archive')

    restore = sub.add_parser('restore', help='put an archive back')
    restore.add_argument('archive')
    restore.add_argument('--target', default=None)
    restore.add_argument('--yes', action='store_true', help='required — a restore replaces the live store')

    listing = sub.add_parser('list', help='what archives exist')
    listing.add_argument('--dir', default=None)

    args = parser.parse_args(argv)

    try:
        if args.command == 'create':
            print(json.dumps(create_backup(args.source, args.out), indent=2))
        elif args.command == 'verify':
            print(json.dumps(verify_backup(args.archive), indent=2))
        elif args.command == 'restore':
            if not args.yes:
                print('Refusing to restore without --yes: this replaces the live decision store.')
                return 2
            print(json.dumps(restore_backup(args.archive, args.target), indent=2))
        elif args.command == 'list':
            print(json.dumps(list_backups(args.dir), indent=2))
    except Exception as exc:  # noqa: BLE001 — a CLI reports, it does not traceback
        print(f'{type(exc).__name__}: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
