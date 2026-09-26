"""Single entry point: GUI without arguments, otherwise the CLI."""

from __future__ import annotations

import sys


def _dependency_error(package: str) -> int:
    """Show an actionable startup error without exposing an import traceback."""
    print(
        f"Не найдена зависимость '{package}'. Установите зависимости проекта:\n"
        "  python -m pip install -r requirements.txt",
        file=sys.stderr,
    )
    return 1


def main() -> int:
    if len(sys.argv) == 1:
        try:
            from gui.app import run_gui
        except ModuleNotFoundError as exc:
            return _dependency_error(exc.name or "customtkinter")
        run_gui()
        return 0
    if "--gui" in sys.argv:
        try:
            from gui.app import run_gui
        except ModuleNotFoundError as exc:
            return _dependency_error(exc.name or "customtkinter")
        run_gui()
        return 0
    # Keep CLI-only dependencies out of the GUI startup path.
    try:
        from cli.app import build_parser, run_cli
    except ModuleNotFoundError as exc:
        return _dependency_error(exc.name or "rich")
    parser = build_parser()
    args = parser.parse_args()
    return run_cli(args)


if __name__ == "__main__":
    raise SystemExit(main())
