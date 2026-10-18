"""Wiederherstellen: Strom prüfen, in temporäre Ordner schreiben, erst dann an den Platz bringen.

Ablauf von :func:`restore_stream` (Vertrag v0.1-Server 3.5):

1. Vor dem Lesen: Ist ein Operator-Tresor da (``vault.json``), endet alles mit ``vault_exists``.
   Ein Terminal als Eingabe gilt nicht (``tty_refused``), ein noch age-verschlüsselter Strom auch
   nicht (Hinweis auf ``--identity`` bzw. Entschlüsseln auf dem Mac).
2. Erstes Mitglied ist das Manifest: Format, Ariadne-Version (nicht neuer als die installierte),
   Struktur, jeder Pfad. Gibt es ein gleichnamiges Projekt, endet alles mit ``project_exists``.
3. Jedes weitere Mitglied muss im Manifest stehen, genau einmal vorkommen, eine reguläre Datei
   oder ein Ordner sein (keine Links, Geräte, FIFOs, keine Sparse-Dateien) und Grösse und SHA-256
   aus dem Manifest haben. Geschrieben wird nur in temporäre Ordner im selben Dateisystem wie die
   Ziele (``.ariadne-restore-<zufall>``), Ordner 0700, Dateien 0600 (0700, wenn die Datei beim
   Sichern für den Besitzer ausführbar war), ohne je einem Link zu folgen.
4. Am Ende des Stroms: fehlt eine Datei, ist alles verworfen. Danach prüft der Ablauf den Inhalt
   (``vault.json`` passt zum Operator-Recipient, ``.vault/manifest.json`` zu Slug und Projekt-ID,
   ``head.json`` zum Kettenkopf im Manifest) und liest den Eingabestrom bis zum Ende, damit ein
   abgeschnittener age-Strom beim Entschlüsseln in der VM auffällt.
5. Erst dann kommen die Ordner an ihren Platz: Projekte, fehlende Konfigurationsdateien
   (vorhandene bleiben), zuletzt der Operator-Tresor. Scheitert ein Schritt, rollt der Ablauf die
   schon verschobenen zurück. Die temporären Ordner verschwinden immer.

Die Ketten selbst lassen sich nur mit Schlüsseln prüfen, die nur der Daemon hält; das macht
``ariadne restore`` nach dem Zurückspielen über ctl (``cli/backup.py``).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import queue
import secrets
import shutil
import stat
import tarfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

import pyrage

from ariadne import __version__
from ariadne.backup.manifest import MANIFEST_NAME, MAX_MANIFEST, check_path, decode_manifest
from ariadne.backup.model import BackupError, RestoreResult
from ariadne.crypto.files import fsync_dir
from ariadne.crypto.vault import VAULT_FORMAT, OperatorVault
from ariadne.paths import Paths, UnsafePathError, ensure_private_dir
from ariadne.project.service import HEAD_FORMAT, MANIFEST_FORMAT

__all__ = ["restore_stream", "DecryptingReader", "is_age_header", "load_identities"]

CHUNK = 1 << 20
MAX_TRAILER = 1 << 20
_AGE_MAGIC = (b"age-encryption.org/", b"-----BEGIN AGE ENCRYPTED FILE-----")
_STAGE_PREFIX = ".ariadne-restore-"


def is_age_header(prefix: bytes) -> bool:
    return any(prefix.startswith(m) for m in _AGE_MAGIC)


def _bad(reason: str) -> BackupError:
    return BackupError("bad_manifest",
                       f"Sicherung beschädigt oder unvollständig ({reason}); nichts geschrieben.")


# --------------------------------------------------------------------------- #
# Eingabe
# --------------------------------------------------------------------------- #


class _PrefixReader:
    """Gibt zuerst die schon gelesenen Bytes zurück, dann den Rest von ``inp``."""

    def __init__(self, prefix: bytes, inp: BinaryIO) -> None:
        self._prefix = prefix
        self._inp = inp

    def read(self, n: int = -1) -> bytes:
        if self._prefix:
            if n is None or n < 0 or n >= len(self._prefix):
                out, self._prefix = self._prefix, b""
                if n is not None and n >= 0 and n > len(out):
                    more = self._inp.read(n - len(out))
                    out += more or b""
                return out
            out, self._prefix = self._prefix[:n], self._prefix[n:]
            return out
        data = self._inp.read(n)
        return data or b""


def _is_tty(stream: Any) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        return False


class DecryptingReader:
    """Entschlüsselt eine age-Datei in einem Thread und liefert den Klartext als Leser.

    Für ``ariadne restore --identity``: Der Klartext liegt nur in einer kleinen Warteschlange im
    Speicher, nie auf der Platte. Ein Fehler beim Entschlüsseln (falscher Schlüssel, beschädigte
    oder abgeschnittene Datei) erscheint beim nächsten :meth:`read` als ``BackupError("decrypt")``.
    """

    _END = object()

    def __init__(self, src: BinaryIO, identities: list[Any]) -> None:
        self._q: queue.Queue[Any] = queue.Queue(maxsize=8)
        self._cancel = threading.Event()
        self._cur = b""
        self._pos = 0
        self._done = False
        self._src = src
        self._idents = identities
        self._thread = threading.Thread(target=self._run, name="ariadne-restore-decrypt", daemon=True)
        self._thread.start()

    def _put(self, item: Any) -> None:
        while not self._cancel.is_set():
            try:
                self._q.put(item, timeout=0.2)
                return
            except queue.Full:
                continue
        raise OSError("abgebrochen")

    def _run(self) -> None:
        reader = self

        class _Sink:
            def write(self, data: Any) -> int:
                reader._put(bytes(data))
                return len(data)

            def flush(self) -> None:
                pass

        try:
            pyrage.decrypt_io(self._src, _Sink(), self._idents)
            self._put(self._END)
        except BaseException as exc:  # noqa: BLE001 (geht an den Leser)
            with contextlib.suppress(OSError):
                self._put(exc)

    def read(self, n: int = -1) -> bytes:
        while self._pos >= len(self._cur):
            if self._done:
                return b""
            item = self._q.get()
            if item is self._END:
                self._done = True
                return b""
            if isinstance(item, BaseException):
                self._done = True
                raise BackupError("decrypt", "Entschlüsseln gescheitert: falscher Schlüssel oder die Datei "
                                             "ist beschädigt bzw. abgeschnitten. Nichts geschrieben.")
            self._cur, self._pos = item, 0
        if n is None or n < 0:
            n = len(self._cur) - self._pos
        out = self._cur[self._pos:self._pos + n]
        self._pos += len(out)
        return out

    def close(self, timeout: float = 5.0) -> None:
        """Beendet den Thread (er bricht beim nächsten Block ab). Hängt er an einer Eingabe, die
        nichts mehr liefert, gibt ``close`` nach ``timeout`` auf; der Thread endet mit dem Prozess."""
        self._cancel.set()
        deadline = time.monotonic() + timeout
        while self._thread.is_alive() and time.monotonic() < deadline:
            with contextlib.suppress(queue.Empty):
                self._q.get(timeout=0.05)
        self._thread.join(timeout=0.1)


def load_identities(text: str) -> list[Any]:
    """age-Identitäten im Format von ``age-keygen`` (Kommentare mit ``#``). Wirft ``decrypt``."""
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            out.append(pyrage.x25519.Identity.from_str(line))
        except Exception:  # noqa: BLE001 (pyrage.IdentityError)
            raise BackupError("decrypt", "Schlüsseldatei ungültig: erwartet wird «AGE-SECRET-KEY-1…» "
                                         "(X25519, wie age-keygen ihn ausgibt).") from None
    if not out:
        raise BackupError("decrypt", "Schlüsseldatei enthält keinen Schlüssel.")
    return out


# --------------------------------------------------------------------------- #
# Temporäre Ordner
# --------------------------------------------------------------------------- #


@dataclass
class _Stage:
    paths: Paths
    roots: dict[str, Path] = field(default_factory=dict)
    created_parents: list[Path] = field(default_factory=list)

    def open(self) -> None:
        token = secrets.token_hex(8)
        parents = {"operator": self.paths.data_dir, "projects": self.paths.projects_root,
                   "config": self.paths.config_dir}
        for key, parent in parents.items():
            missing = [p for p in (parent, *parent.parents) if not os.path.lexists(p)]
            try:
                ensure_private_dir(parent)
            except (OSError, UnsafePathError) as exc:
                raise BackupError("io", "Zielordner der Installation nicht nutzbar (Symlink, fremder "
                                        "Besitzer oder keine Rechte).") from exc
            self.created_parents += [p for p in missing if p.is_dir()]
            root = parent / f"{_STAGE_PREFIX}{token}"
            os.mkdir(root, 0o700)
            self.roots[key] = root

    def path_for(self, arc: str) -> Path:
        parts = arc.split("/")
        if parts[0] == "projects":
            return self.roots["projects"].joinpath(*parts[1:])
        return self.roots[parts[0]].joinpath(*parts)

    def cleanup(self, *, failed: bool) -> None:
        for root in self.roots.values():
            shutil.rmtree(root, ignore_errors=True)
        if failed:  # selbst angelegte, leere Standardordner wieder weg (tiefste zuerst)
            for p in sorted(set(self.created_parents), key=lambda x: len(x.parts), reverse=True):
                with contextlib.suppress(OSError):
                    p.rmdir()


def _mkdirs(base: Path, target: Path) -> None:
    """Legt alle Ordner zwischen ``base`` (existiert) und ``target`` mit 0700 an, ohne Links."""
    rel = target.relative_to(base)
    cur = base
    for part in rel.parts:
        cur = cur / part
        try:
            os.mkdir(cur, 0o700)
        except FileExistsError:
            st = os.lstat(cur)
            if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
                raise BackupError("unsafe_path", "Pfadkonflikt in der Sicherung (Datei und Ordner "
                                                 "gleichnamig); nichts geschrieben.") from None


def _base_of(stage: _Stage, arc: str) -> Path:
    head = arc.split("/")[0]
    return stage.roots["projects" if head == "projects" else head]


# --------------------------------------------------------------------------- #
# Prüfungen des Inhalts
# --------------------------------------------------------------------------- #


def _read_json(path: Path, max_size: int = 1 << 20) -> Any:
    with open(path, "rb") as fh:
        data = fh.read(max_size + 1)
    if len(data) > max_size:
        raise ValueError("zu gross")
    return json.loads(data.decode("utf-8"))


def _check_content(stage: _Stage, doc: dict[str, Any]) -> None:
    try:
        meta = _read_json(stage.path_for("operator/vault.json"))
    except (OSError, ValueError, UnicodeDecodeError):
        raise _bad("vault.json unlesbar") from None
    if not isinstance(meta, dict) or meta.get("format") != VAULT_FORMAT or \
            meta.get("recipient") != doc["operator"]["recipient"]:
        raise _bad("Operator-Tresor passt nicht zum Manifest")
    for p in doc["projects"]:
        slug = p["slug"]
        try:
            pm = _read_json(stage.path_for(f"projects/{slug}/.vault/manifest.json"))
        except (OSError, ValueError, UnicodeDecodeError):
            raise _bad(f"Projekt {slug}: manifest.json unlesbar") from None
        if not isinstance(pm, dict) or pm.get("format") != MANIFEST_FORMAT or pm.get("slug") != slug or \
                pm.get("project_id") != p["project_id"]:
            raise _bad(f"Projekt {slug}: manifest.json passt nicht")
        head = p.get("head")
        if head is not None:
            try:
                h = _read_json(stage.path_for(f"projects/{slug}/.vault/head.json"), 4096)
            except (OSError, ValueError, UnicodeDecodeError):
                raise _bad(f"Projekt {slug}: head.json fehlt") from None
            if not isinstance(h, dict) or h.get("format") != HEAD_FORMAT or \
                    h.get("project_id") != p["project_id"] or h.get("head_seq") != head["head_seq"] or \
                    h.get("head_hash") != head["head_hash"]:
                raise BackupError("hash_mismatch", f"Projekt {slug}: Kettenkopf passt nicht zum Manifest; "
                                                   "nichts geschrieben.")


# --------------------------------------------------------------------------- #
# Strom lesen
# --------------------------------------------------------------------------- #


def _write_member(tf: tarfile.TarFile, m: tarfile.TarInfo, dest: Path, spec: dict[str, Any]) -> None:
    size = int(spec["size"])
    if m.size != size:
        raise BackupError("hash_mismatch", "Grösse einer Datei passt nicht zum Manifest; nichts geschrieben.")
    mode = 0o700 if int(spec.get("mode", 0)) & stat.S_IXUSR else 0o600
    src = tf.extractfile(m)
    if src is None:
        raise _bad("Datei ohne Inhalt")
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        h = hashlib.sha256()
        n = 0
        while True:
            chunk = src.read(CHUNK)
            if not chunk:
                break
            n += len(chunk)
            if n > size:
                raise BackupError("hash_mismatch", "Datei länger als im Manifest; nichts geschrieben.")
            h.update(chunk)
            view = memoryview(chunk)
            while view:
                view = view[os.write(fd, view):]
        if n != size:
            raise _bad("Datei abgeschnitten")
        if not secrets.compare_digest(h.hexdigest(), str(spec["sha256"])):
            raise BackupError("hash_mismatch", "SHA-256 einer Datei passt nicht zum Manifest (Sicherung "
                                               "beschädigt oder verändert); nichts geschrieben.")
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)
    mtime = m.mtime if isinstance(m.mtime, int | float) else None
    if mtime is not None and 0 <= mtime < 1 << 40:
        with contextlib.suppress(OSError):
            os.utime(dest, (mtime, mtime), follow_symlinks=False)


def _read_stream(tf: tarfile.TarFile,
                 opened: Callable[[dict[str, Any]], _Stage]) -> tuple[dict[str, Any], str, _Stage]:
    it = iter(tf)
    first = next(it, None)
    if first is None or first.name != MANIFEST_NAME or first.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) \
            or first.size > MAX_MANIFEST:
        raise _bad("Manifest fehlt am Anfang")
    fh = tf.extractfile(first)
    raw = fh.read(first.size + 1) if fh is not None else b""
    if len(raw) != first.size:
        raise _bad("Manifest abgeschnitten")
    doc = decode_manifest(raw, __version__)
    manifest_sha = hashlib.sha256(raw).hexdigest()
    stage = opened(doc)
    files = {f["path"]: f for f in doc["files"]}
    dirs = {d["path"] for d in doc["dirs"]}
    slugs = {p["slug"] for p in doc["projects"]}
    seen: set[str] = set()
    for m in it:
        name = m.name
        if name in seen:
            raise _bad("Eintrag doppelt")
        seen.add(name)
        if m.type == tarfile.DIRTYPE:
            if name not in dirs:
                raise _bad("unerwarteter Ordner")
            check_path(name, slugs=slugs, is_dir=True)
            dest = stage.path_for(name)
            _mkdirs(_base_of(stage, name), dest)
            continue
        if m.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or m.sparse is not None:
            raise BackupError("unsafe_path", "Die Sicherung enthält einen Link, ein Gerät oder einen anderen "
                                             "unzulässigen Eintrag; nichts geschrieben.")
        spec = files.get(name)
        if spec is None:
            raise _bad("unerwartete Datei")
        check_path(name, slugs=slugs)
        dest = stage.path_for(name)
        _mkdirs(_base_of(stage, name), dest.parent)
        _write_member(tf, m, dest, spec)
    missing = [p for p in files if p not in seen]
    if missing:
        raise _bad(f"{len(missing)} Dateien fehlen")
    for d in sorted(dirs - seen):
        _mkdirs(_base_of(stage, d), stage.path_for(d))
    return doc, manifest_sha, stage


def _drain(inp: Any) -> None:
    """Liest bis zum Ende: Nach dem Tar-Ende sind nur Nullen erlaubt (höchstens 1 MiB)."""
    total = 0
    while True:
        chunk = inp.read(1 << 16)
        if not chunk:
            return
        total += len(chunk)
        if total > MAX_TRAILER or chunk.count(0) != len(chunk):
            raise _bad("Daten nach dem Ende")


# --------------------------------------------------------------------------- #
# An den Platz bringen
# --------------------------------------------------------------------------- #


def _replaceable(target: Path) -> bool:
    """Ziel fehlt oder ist ein leerer, echter Ordner (wird ersetzt)."""
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        return True
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return False
    try:
        with os.scandir(target) as it:
            return next(it, None) is None
    except OSError:
        return False


def _vault_present(paths: Paths) -> bool:
    return OperatorVault(paths.operator_dir).exists or not _replaceable(paths.operator_dir)


def _fsync_tree(root: Path) -> None:
    for dirpath, _dirnames, _files in os.walk(root, followlinks=False):
        with contextlib.suppress(OSError):
            fsync_dir(Path(dirpath))


@dataclass
class _Commit:
    moved: list[tuple[Path, Path]] = field(default_factory=list)  # (Ziel, temporär)
    added: list[Path] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)
    added_rel: list[str] = field(default_factory=list)

    def rollback(self) -> None:
        for target, tmp in reversed(self.moved):
            with contextlib.suppress(OSError):
                os.rename(target, tmp)
        for f in self.added:
            with contextlib.suppress(OSError):
                os.unlink(f)


def _move_dir(tmp: Path, target: Path, commit: _Commit, code: str, message: str) -> None:
    if not _replaceable(target):
        raise BackupError(code, message)
    with contextlib.suppress(FileNotFoundError):
        os.rmdir(target)
    _fsync_tree(tmp)
    try:
        os.rename(tmp, target)
    except OSError as exc:
        raise BackupError(code if os.path.lexists(target) else "io", message) from exc
    commit.moved.append((target, tmp))
    fsync_dir(target.parent)


def _merge_config(stage: _Stage, paths: Paths, commit: _Commit) -> None:
    src_root = stage.roots["config"] / "config"
    if not src_root.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(src_root, followlinks=False):
        dirnames.sort()
        rel_dir = Path(dirpath).relative_to(src_root)
        for name in sorted(filenames):
            rel = rel_dir / name
            target = paths.config_dir / rel
            try:
                _mkdirs(paths.config_dir, target.parent)
            except BackupError:
                commit.kept.append(str(rel))
                continue
            if os.path.lexists(target):
                commit.kept.append(str(rel))
                continue
            try:
                os.link(Path(dirpath) / name, target, follow_symlinks=False)
            except FileExistsError:
                commit.kept.append(str(rel))
                continue
            except OSError:  # Dateisystem ohne harte Links
                if os.path.lexists(target):
                    commit.kept.append(str(rel))
                    continue
                os.rename(Path(dirpath) / name, target)
            commit.added.append(target)
            commit.added_rel.append(str(rel))
            with contextlib.suppress(OSError):
                fsync_dir(target.parent)


def _commit(stage: _Stage, paths: Paths, doc: dict[str, Any]) -> _Commit:
    commit = _Commit()
    try:
        if _vault_present(paths):
            raise BackupError("vault_exists", "Es gibt schon einen Operator-Tresor; nichts geschrieben.")
        for p in doc["projects"]:
            slug = p["slug"]
            _move_dir(stage.roots["projects"] / slug, paths.projects_root / slug, commit, "project_exists",
                      f"Projekt {slug} existiert schon; nichts geschrieben.")
        _merge_config(stage, paths, commit)
        _move_dir(stage.roots["operator"] / "operator", paths.operator_dir, commit, "vault_exists",
                  "Es gibt schon einen Operator-Tresor; nichts geschrieben.")
    except BaseException:
        commit.rollback()
        raise
    return commit


# --------------------------------------------------------------------------- #
# Einstieg
# --------------------------------------------------------------------------- #


def restore_stream(inp: BinaryIO, paths: Paths) -> RestoreResult:
    """Siehe Modulbeschreibung. ``inp`` ist der entschlüsselte innere Strom."""
    if _vault_present(paths):
        raise BackupError("vault_exists",
                          "Hier gibt es schon einen Operator-Tresor. Wiederherstellen geht nur in eine "
                          "Installation ohne Tresor (frische VM: ariadne setup, aber nicht ariadne init).")
    if _is_tty(inp):
        raise BackupError("tty_refused", "Die Sicherung kommt über eine Pipe oder --from-file, nicht von "
                                         "einem Terminal.")
    prefix = inp.read(tarfile.BLOCKSIZE) or b""
    if not prefix:
        raise _bad("leere Eingabe")
    if is_age_header(prefix):
        raise BackupError("decrypt", "Die Eingabe ist noch age-verschlüsselt. Auf dem Mac entschlüsseln "
                                     "(age -d -i … DATEI | ssh kali-sl restore) oder in der VM mit "
                                     "ariadne restore --from-file DATEI --identity SCHLÜSSELDATEI.")
    reader = _PrefixReader(prefix, inp)

    stage: _Stage | None = None

    def opened(doc: dict[str, Any]) -> _Stage:
        nonlocal stage
        for p in doc["projects"]:
            if not _replaceable(paths.projects_root / p["slug"]):
                raise BackupError("project_exists", f"Projekt {p['slug']} existiert hier schon; nichts "
                                                    f"geschrieben.")
        stage = _Stage(paths)
        stage.open()
        return stage

    failed = True
    try:
        try:
            with tarfile.open(fileobj=reader, mode="r|", encoding="utf-8", errors="surrogateescape") as tf:
                doc, manifest_sha, stage = _read_stream(tf, opened)
            _drain(reader)
        except BackupError:
            raise
        except (tarfile.TarError, EOFError, UnicodeError, ValueError, KeyError) as exc:
            raise _bad("Tar-Strom ungültig") from exc
        except OSError as exc:
            raise BackupError("io", "Lesen oder Schreiben beim Wiederherstellen gescheitert; nichts "
                                    "geschrieben.") from exc
        _check_content(stage, doc)
        commit = _commit(stage, paths, doc)
        failed = False
    finally:
        if stage is not None:
            stage.cleanup(failed=failed)
    heads = {p["slug"]: p["head"]["head_hash"] for p in doc["projects"] if p.get("head")}
    seqs = {p["slug"]: int(p["head"]["head_seq"]) for p in doc["projects"] if p.get("head")}
    return RestoreResult(
        projects=tuple(p["slug"] for p in doc["projects"]), operator_restored=True, verified={},
        chain_heads=heads, head_seqs=seqs, config_added=tuple(commit.added_rel),
        config_kept=tuple(commit.kept), files=len(doc["files"]), manifest_sha256=manifest_sha,
        backup_id=str(doc["backup_id"]), created_utc=str(doc["created_utc"]),
        ariadne_version=str(doc["ariadne_version"]),
    )
