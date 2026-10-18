"""``ariadne doctor`` (minimal, Architektur 8.4, 8.6): prüft, was v0.1 braucht.

Dazu die gebaute Weboberfläche (``src/ariadne/web/static``): Der Build ist eingecheckt und liegt im
Wheel. ``scripts/build-ui.sh`` baut sie und schreibt den Build-Vermerk :data:`UI_MANIFEST` mit dem
Hash der webui-Quellen und dem Hash jeder gebauten Datei. ``doctor`` meldet eine fehlende,
unvollständige oder (in einem Checkout mit ``webui/``) veraltete Oberfläche.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ariadne.cli.setup import MARK_BEGIN, SHELL_FILES
from ariadne.paths import Paths

__all__ = [
    "Check",
    "run_checks",
    "swap_check",
    "UI_MANIFEST",
    "ui_check",
    "ui_source_hash",
    "ui_files",
    "ui_refs",
    "write_ui_manifest",
    "static_dir",
    "webui_dir",
]

OK, WARN, FAIL = "ok", "warn", "fail"


@dataclass(frozen=True)
class Check:
    level: str
    title: str
    detail: str = ""


def _python() -> Check:
    v = sys.version_info
    lvl = OK if v >= (3, 11) else FAIL
    return Check(lvl, f"Python {v.major}.{v.minor}.{v.micro}", "" if lvl == OK else "mindestens 3.11 nötig")


def _imports() -> list[Check]:
    out = []
    for mod in ("sqlcipher3", "pyrage", "tomlkit", "pydantic"):
        try:
            importlib.import_module(mod)
            out.append(Check(OK, f"Modul {mod}"))
        except ImportError:
            out.append(Check(FAIL, f"Modul {mod} fehlt", "pipx reinstall ariadne-recon"))
    return out


def _shell_files(paths: Paths) -> Check:
    missing = [n for n in (*SHELL_FILES, "env.sh") if not (paths.shell_dir / n).is_file()]
    if missing:
        return Check(FAIL, "Shell-Integration unvollständig",
                     "fehlt: " + ", ".join(missing) + " (ariadne setup)")
    return Check(OK, "Shell-Integration installiert")


def _rc_blocks(paths: Paths) -> list[Check]:
    out = []
    for rc in (".zshrc", ".bashrc"):
        p = paths.home / rc
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            out.append(Check(WARN, f"~/{rc} fehlt"))
            continue
        first = next((ln for ln in text.splitlines() if ln.strip()), "")
        if MARK_BEGIN not in text:
            out.append(Check(WARN, f"~/{rc}: kein Ariadne-Block", "ariadne setup"))
        elif first != MARK_BEGIN:
            out.append(Check(WARN, f"~/{rc}: Ariadne-Block nicht ganz oben"))
        else:
            out.append(Check(OK, f"~/{rc}: Ariadne-Block ganz oben"))
    return out


def _socket_dir(paths: Paths) -> Check:
    d = paths.runtime_dir
    note = "" if os.environ.get("XDG_RUNTIME_DIR") else " (ohne XDG_RUNTIME_DIR, Ausweichordner)"
    try:
        st = os.lstat(d)
    except FileNotFoundError:
        return Check(OK, "Socket-Ordner wird beim Start angelegt" + note)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return Check(FAIL, "Socket-Ordner ist kein echter Ordner", str(d))
    if st.st_uid != os.getuid():
        return Check(FAIL, "Socket-Ordner gehört einem anderen Benutzer", str(d))
    if st.st_mode & 0o077:
        return Check(FAIL, "Socket-Ordner ist für andere lesbar", f"chmod 700 {d}")
    return Check(OK, "Socket-Ordner sicher (0700)" + note)


def _run(argv: list[str]) -> str | None:
    env = dict(os.environ, ARIADNE_DISABLE="1")
    try:
        res = subprocess.run(argv, capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL,
                             env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return res.stdout


def _grep_files(files: list[Path], pattern: str) -> bool:
    rx = re.compile(pattern, re.M | re.I)
    for f in files:
        try:
            if rx.search(f.read_text(encoding="utf-8", errors="replace")):
                return True
        except OSError:
            continue
    return False


def _bracketed_paste(paths: Paths) -> list[Check]:
    out = []
    zsh = shutil.which("zsh")
    if zsh:
        # Statisch geprüft: eine interaktive zsh ohne TTY lädt ZLE nicht und sagt nichts Verlässliches.
        ver = re.search(r"zsh (\d+)\.(\d+)", _run([zsh, "--version"]) or "")
        off = _grep_files([paths.home / ".zshrc", paths.home / ".zshenv", paths.home / ".zprofile",
                           Path("/etc/zsh/zshrc"), Path("/etc/zshrc")],
                          r"^\s*(unset\s+zle_bracketed_paste|zle_bracketed_paste=\(\s*\))")
        if off:
            out.append(Check(WARN, "zsh: Bracketed Paste abgeschaltet", "zle_bracketed_paste nicht leeren"))
        elif ver and (int(ver.group(1)), int(ver.group(2))) >= (5, 1):
            out.append(Check(OK, "zsh: Bracketed Paste aktiv (Standard ab 5.1)"))
        else:
            out.append(Check(WARN, "zsh: Bracketed Paste unbekannt"))
    bash = shutil.which("bash")
    if bash:
        bver = _run([bash, "-c", "echo ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"]) or ""
        off = _grep_files([paths.home / ".inputrc", Path("/etc/inputrc")],
                          r"^\s*set\s+enable-bracketed-paste\s+off")
        try:
            new_enough = tuple(int(x) for x in bver.strip().split(".")) >= (5, 1)
        except ValueError:
            new_enough = False
        if off:
            out.append(Check(WARN, "bash: Bracketed Paste in inputrc abgeschaltet"))
        elif new_enough:
            out.append(Check(OK, "bash: Bracketed Paste aktiv (Standard ab 5.1)"))
        else:
            out.append(Check(WARN, "bash: Bracketed Paste unbekannt", "bash vor 5.1"))
    return out


def _ptrace() -> Check:
    try:
        val = Path("/proc/sys/kernel/yama/ptrace_scope").read_text().strip()
    except OSError:
        return Check(WARN, "kernel.yama.ptrace_scope unbekannt", "Yama fehlt")
    if val == "0":
        return Check(WARN, "kernel.yama.ptrace_scope = 0",
                     "jeder Prozess des Benutzers darf andere auslesen; 1 empfohlen")
    return Check(OK, f"kernel.yama.ptrace_scope = {val}")


def _crypted(name: str, dm_uuid: Callable[[str], str | None],
             slaves: Callable[[str], list[str]], depth: int = 0) -> bool:
    """Liegt das Gerät auf dm-crypt? Auch über Zwischenschichten (LVM auf LUKS, Kali-Standard)."""
    if not name.startswith("dm-") or depth > 8:
        return False
    if (dm_uuid(name) or "").startswith("CRYPT-"):
        return True
    return any(_crypted(sl, dm_uuid, slaves, depth + 1) for sl in slaves(name))


def swap_check(swaps: str, dm_uuid: Callable[[str], str | None],
               slaves: Callable[[str], list[str]] | None = None,
               file_dev: Callable[[str], str | None] | None = None) -> Check:
    """Vorlauf und Puffer liegen nur im RAM (E95); unverschlüsselter Swap kann sie auf die Platte bringen.

    ``swaps`` ist der Inhalt von ``/proc/swaps``; zram und dm-crypt gelten als sicher, auch
    unter LVM (``slaves``: die Geräte unter einem dm-Gerät). Eine Swap-Datei zählt nach dem
    Gerät ihres Dateisystems (``file_dev``).
    """
    under = slaves or (lambda _n: [])
    unsafe = []
    for line in swaps.splitlines()[1:]:
        parts = line.split()
        dev = parts[0] if parts else ""
        name = os.path.basename(dev)
        if not dev or name.startswith("zram"):
            continue
        if len(parts) > 1 and parts[1] == "file" and file_dev is not None:
            name = file_dev(dev) or name
        if _crypted(name, dm_uuid, under):
            continue
        unsafe.append(dev)
    if unsafe:
        return Check(WARN, "Swap unverschlüsselt", "Vorlauf und Puffer können ausgelagert werden: "
                     + ", ".join(unsafe[:3]) + " (zram oder verschlüsselten Swap verwenden)")
    return Check(OK, "Swap: keiner, zram oder verschlüsselt")


def _swap() -> Check:
    def dm_uuid(name: str) -> str | None:
        try:
            return Path(f"/sys/block/{name}/dm/uuid").read_text().strip()
        except OSError:
            return None

    def slaves(name: str) -> list[str]:
        try:
            return sorted(os.listdir(f"/sys/block/{name}/slaves"))
        except OSError:
            return []

    def file_dev(path: str) -> str | None:
        try:
            dev = os.stat(path).st_dev
            return os.path.basename(os.readlink(f"/sys/dev/block/{os.major(dev)}:{os.minor(dev)}"))
        except OSError:
            return None

    try:
        swaps = Path("/proc/swaps").read_text()
    except OSError:
        return Check(WARN, "Swap unbekannt", "/proc/swaps nicht lesbar")
    return swap_check(swaps, dm_uuid, slaves, file_dev)


# --------------------------------------------------------------------------- Weboberfläche

UI_MANIFEST = ".build-info.json"  # versteckt: der Webserver liefert keine Punktdateien aus
_UI_FORMAT = 1
# Was den Build bestimmt (relativ zu webui/). Tests und Werkzeug-Konfiguration zählen nicht.
_UI_SOURCE_FILES = (
    "index.html",
    "package.json",
    "package-lock.json",
    "vite.config.ts",
    "svelte.config.js",
    "tsconfig.json",
)
_UI_SOURCE_DIRS = ("src", "public")
_UI_SKIP = re.compile(r"\.(test|spec)\.ts$")
_UI_REF_HTML = re.compile(r'(?:src|href)="/([^"?#]+)"')
_UI_REF_ASSET = re.compile(r"(?<![A-Za-z0-9_./-])(assets/[A-Za-z0-9_.-]+\.(?:js|css|svg|png|woff2))")
_UI_REF_REL = re.compile(r"""["'`]\./([A-Za-z0-9_.-]+\.(?:js|css))["'`]""")  # Chunk neben dem Chunk
_UI_REF_ROOT = re.compile(r"""["'`]/([A-Za-z0-9_.-]+\.(?:svg|png|ico))["'`]""")  # Favicons


def static_dir() -> Path:
    """Ordner der gebauten Oberfläche im installierten Paket."""
    import ariadne

    return Path(ariadne.__file__).resolve().parent / "web" / "static"


def webui_dir() -> Path | None:
    """``webui/`` eines Checkouts (editierbare Installation), sonst ``None`` (Wheel)."""
    import ariadne

    cand = Path(ariadne.__file__).resolve().parents[2] / "webui"
    return cand if (cand / "package.json").is_file() and (cand / "src").is_dir() else None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _ui_sources(webui: Path) -> list[tuple[str, Path]]:
    out: list[tuple[str, Path]] = []
    for name in _UI_SOURCE_FILES:
        if (webui / name).is_file():
            out.append((name, webui / name))
    for d in _UI_SOURCE_DIRS:
        base = webui / d
        if not base.is_dir():
            continue
        for f in base.rglob("*"):
            rel = f.relative_to(webui).as_posix()
            if f.is_file() and not f.is_symlink() and not _UI_SKIP.search(rel):
                out.append((rel, f))
    return sorted(out)


def ui_source_hash(webui: Path) -> str:
    """Hash des Quellstands der Oberfläche: Pfade und Inhalte der Dateien, die den Build bestimmen."""
    h = hashlib.sha256()
    for rel, f in _ui_sources(webui):
        h.update(f"{rel}\0{_sha256(f)}\n".encode())
    return h.hexdigest()


def ui_files(static: Path) -> dict[str, str]:
    """Alle gebauten Dateien (ohne den Vermerk) mit ihrem SHA-256."""
    out: dict[str, str] = {}
    if not static.is_dir():
        return out
    for f in sorted(static.rglob("*")):
        rel = f.relative_to(static).as_posix()
        if f.is_file() and rel != UI_MANIFEST and "__pycache__" not in rel:
            out[rel] = _sha256(f)
    return out


def ui_refs(static: Path) -> set[str]:
    """Von ``index.html`` und den gebauten Skripten und Stilen verlangte Dateien (relativ zu static)."""
    refs: set[str] = set()
    index = static / "index.html"
    if index.is_file():
        refs |= set(_UI_REF_HTML.findall(index.read_text(encoding="utf-8", errors="replace")))
    for f in static.glob("assets/*"):
        if f.suffix in (".js", ".css") and f.is_file():
            text = f.read_text(encoding="utf-8", errors="replace")
            refs |= set(_UI_REF_ASSET.findall(text))
            refs |= {f"assets/{n}" for n in _UI_REF_REL.findall(text)}
            refs |= set(_UI_REF_ROOT.findall(text))
    return refs


def write_ui_manifest(static: Path, webui: Path) -> dict[str, object]:
    """Build-Vermerk schreiben (nach ``npm run build``, aufgerufen von ``scripts/build-ui.sh``)."""
    data: dict[str, object] = {
        "format": _UI_FORMAT,
        "source_sha256": ui_source_hash(webui),
        "files": ui_files(static),
    }
    (static / UI_MANIFEST).write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return data


def ui_check(static: Path | None = None, webui: Path | None = None, *, checkout: bool = True) -> Check:
    """Ist die gebaute Oberfläche vollständig, unverändert und (im Checkout) aktuell?"""
    static = static or static_dir()
    if webui is None and checkout:
        webui = webui_dir()
    fix = "scripts/build-ui.sh" if webui is not None else "pipx reinstall ariadne-recon"
    if not (static / "index.html").is_file():
        return Check(FAIL, "Weboberfläche fehlt", f"index.html nicht gefunden ({fix})")
    try:
        manifest = json.loads((static / UI_MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        manifest = None
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), dict):
        return Check(WARN, "Weboberfläche ohne Build-Vermerk", f"Stand unbekannt ({fix})")
    have = ui_files(static)
    want = {str(k): v for k, v in manifest["files"].items()}
    missing = sorted(set(want) - set(have))
    changed = sorted(k for k in want if k in have and have[k] != want[k])
    unref = sorted(r for r in ui_refs(static) if r not in have)
    if missing or changed or unref:
        names = (missing + changed + unref)[:3]
        return Check(FAIL, "Weboberfläche unvollständig oder verändert", ", ".join(names) + f" ({fix})")
    src = manifest.get("source_sha256")
    if webui is not None and src != ui_source_hash(webui):
        return Check(WARN, "Weboberfläche veraltet", f"webui-Quellen geändert seit dem Build ({fix})")
    return Check(OK, f"Weboberfläche vorhanden (Quellstand {str(src)[:12]})")


def run_checks(paths: Paths) -> list[Check]:
    return [
        _python(),
        *_imports(),
        ui_check(),
        _shell_files(paths),
        *_rc_blocks(paths),
        _socket_dir(paths),
        *_bracketed_paste(paths),
        _ptrace(),
        _swap(),
    ]
