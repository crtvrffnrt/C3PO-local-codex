#!/usr/bin/env python3
"""Load and safely select a Codex model from the local CLI catalog."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from typing import Any


def clean_text(value: Any) -> str:
    return str(value).replace("\r", " ").replace("\n", " ").strip() if value is not None else ""


def load_catalog() -> tuple[dict[str, Any] | None, str]:
    if not shutil.which("codex"):
        return None, "codex CLI is not installed"
    try:
        result = subprocess.run(["codex", "debug", "models"], text=True, capture_output=True, timeout=30)
    except Exception as exc:
        return None, f"codex debug models could not run: {exc}"
    if result.returncode != 0:
        return None, f"codex debug models failed with exit code {result.returncode}"
    if not result.stdout.strip():
        return None, "codex debug models returned empty output"
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return None, f"codex debug models returned malformed JSON: {exc}"
    models = data.get("models") if isinstance(data, dict) else None
    if not isinstance(models, list) or not models:
        return None, "Codex model catalog has no non-empty models array"
    valid = []
    for index, model in enumerate(models):
        if not isinstance(model, dict) or not clean_text(model.get("slug")):
            print(f"[!] Ignoring malformed Codex catalog model entry at index {index}.", file=sys.stderr)
            continue
        valid.append(model)
    if not valid:
        return None, "Codex model catalog contains no usable model slugs"
    return {"models": valid}, ""


def find_model(catalog: dict[str, Any], slug: str) -> dict[str, Any] | None:
    return next((m for m in catalog["models"] if clean_text(m.get("slug")) == slug), None)


def efforts(model: dict[str, Any]) -> list[str]:
    return [clean_text(item.get("effort")) for item in model.get("supported_reasoning_levels", [])
            if isinstance(item, dict) and clean_text(item.get("effort"))]


def prompt(text: str) -> str:
    print(text, end="", file=sys.stderr, flush=True)
    return sys.stdin.readline()


def validate(catalog: dict[str, Any], model_slug: str, effort: str) -> tuple[dict[str, Any] | None, str]:
    model = find_model(catalog, model_slug)
    if not model:
        return None, f"Invalid Codex model '{model_slug}'. Available slugs: " + ", ".join(clean_text(m.get("slug")) for m in catalog["models"])
    if effort:
        supported = efforts(model)
        if supported and effort not in supported:
            return None, f"Unsupported reasoning effort '{effort}' for model '{model_slug}'. Supported efforts: {', '.join(supported)}"
        if not supported and clean_text(model.get("default_reasoning_level")) != effort:
            return None, f"Model '{model_slug}' exposes no supported efforts and its catalog default is '{clean_text(model.get('default_reasoning_level')) or 'unset'}'"
    return {"model": model_slug, "model_display_name": clean_text(model.get("display_name")), "reasoning": effort,
            "catalog_default_reasoning": clean_text(model.get("default_reasoning_level"))}, ""


def choose(catalog: dict[str, Any]) -> dict[str, Any] | None:
    out = lambda *args: print(*args, file=sys.stderr)
    out("\nAvailable Codex models:")
    for number, model in enumerate(catalog["models"], 1):
        slug, name = clean_text(model.get("slug")), clean_text(model.get("display_name"))
        out(f"  {number}) {name} ({slug})" if name else f"  {number}) {slug}")
    out("  0) Continue without Codex")
    while True:
        try:
            raw = prompt("Select model: ").strip()
        except EOFError:
            return None
        if raw == "0":
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(catalog["models"]):
            model = catalog["models"][int(raw) - 1]
            break
        print("[!] Enter a whole-number menu selection.", file=sys.stderr)
    supported = efforts(model)
    default = clean_text(model.get("default_reasoning_level"))
    out(f"\nSelected model: {clean_text(model.get('display_name')) or clean_text(model.get('slug'))} ({clean_text(model.get('slug'))})")
    out("\nAvailable reasoning efforts:")
    for number, item in enumerate(supported, 1):
        out(f"  {number}) {item}{' [default]' if item == default else ''}")
    if not supported and default:
        out(f"  Catalog default: {default} (no supported-effort list was provided)")
    while True:
        try:
            raw = prompt("Select effort" + (" [default]" if default in supported else "") + ": ").strip()
        except EOFError:
            return None
        if not raw and default and (default in supported or not supported):
            effort = default
            break
        if raw.isdigit() and 1 <= int(raw) <= len(supported):
            effort = supported[int(raw) - 1]
            break
        print("[!] Enter a whole-number menu selection or a valid default.", file=sys.stderr)
    return {"model": clean_text(model.get("slug")), "model_display_name": clean_text(model.get("display_name")),
            "reasoning": effort, "catalog_default_reasoning": default}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=os.environ.get("CODEX_MODEL", ""))
    parser.add_argument("--reasoning", default=os.environ.get("CODEX_REASONING", ""))
    parser.add_argument("--no-codex", action="store_true")
    parser.add_argument("--interactive", action="store_true")
    args = parser.parse_args()
    if args.no_codex:
        print(json.dumps({"enabled": False, "reason": "intentionally disabled"}))
        return 0
    catalog, error = load_catalog()
    if not catalog:
        print(f"[!] {error}; deterministic prioritization will be used.", file=sys.stderr)
        print(json.dumps({"enabled": False, "catalog_loaded": False, "catalog_error": error}))
        return 0 if not (args.model or args.reasoning or args.interactive) else 0
    if args.model or args.reasoning:
        if not args.model:
            print("[!] --codex-reasoning requires --codex-model.", file=sys.stderr)
            return 2
        selected, error = validate(catalog, args.model, args.reasoning)
    elif args.interactive:
        selected, error = choose(catalog), ""
    else:
        print(json.dumps({"enabled": False, "catalog_loaded": True, "catalog_error": ""}))
        return 0
    if error:
        print(f"[!] {error}", file=sys.stderr)
        return 2
    if not selected:
        print(json.dumps({"enabled": False, "catalog_loaded": True, "catalog_error": ""}))
        return 0
    selected.update({"enabled": True, "catalog_loaded": True, "catalog_error": ""})
    print(json.dumps(selected))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
