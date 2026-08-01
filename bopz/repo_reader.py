"""Acceso al código fuente: GitHub URL o directorio local.

Si se pasa una URL de GitHub, clona el repo en un directorio temporal
y devuelve la ruta local. Si se pasa un path local, lo devuelve tal cual.
El directorio temporal se limpia automáticamente al salir del context manager.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager


def is_github_url(repo: str) -> bool:
    return repo.startswith(("https://github.com", "http://github.com",
                             "git@github.com", "github.com"))


@contextmanager
def open_repo(repo: str, branch: str | None = None):
    """Context manager que devuelve la ruta local al código fuente.

    Uso:
        with open_repo("https://github.com/user/repo") as path:
            # path es un directorio temporal con el código clonado
    """
    if not is_github_url(repo):
        # Path local — no necesitamos clonar nada
        if not os.path.isdir(repo):
            raise FileNotFoundError(f"Directorio no encontrado: {repo}")
        yield repo
        return

    tmpdir = tempfile.mkdtemp(prefix="bopz-repo-")
    try:
        cmd = ["git", "clone", "--depth", "1", "--quiet"]
        if branch:
            cmd += ["--branch", branch]
        cmd += [repo, tmpdir]

        print(f"[BopZ] Clonando repositorio: {repo}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise RuntimeError(
                f"git clone falló:\n{result.stderr.strip()}"
            )
        print(f"[BopZ] Repositorio clonado en {tmpdir}")
        yield tmpdir
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def collect_source_files(repo_path: str,
                          extensions: tuple = (".py", ".js", ".ts", ".env",
                                                ".json", ".yaml", ".yml",
                                                ".toml", ".cfg", ".ini",
                                                ".properties", ".xml"),
                          exclude_dirs: tuple = (".git", "__pycache__",
                                                  "node_modules", ".venv",
                                                  "venv", "dist", "build")
                          ) -> list[str]:
    """Devuelve rutas absolutas de todos los archivos de código del repo."""
    files = []
    for root, dirs, filenames in os.walk(repo_path):
        # Excluir directorios que no son código
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for fname in filenames:
            if any(fname.endswith(ext) for ext in extensions):
                files.append(os.path.join(root, fname))
    return files
