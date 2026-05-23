#!/usr/bin/env python3
"""reconai — AI-augmented subdomain and endpoint enumeration."""

# ── Imports ────────────────────────────────────────────────
import argparse
import datetime
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time

import anthropic
from typing import Optional

# ── Constants ──────────────────────────────────────────────
DEFAULT_MODEL = "claude-sonnet-4-6"
DEFAULT_ROUNDS = 3
DEFAULT_DELAY = 1.0
DEFAULT_CANDIDATES = 50
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

REQUIRED_BINARIES = {
    "domain": ["subfinder", "dnsx", "httpx"],
    "url": ["httpx"],
    "llm": ["dnsx", "httpx"],
}


# ── Utility functions ───────────────────────────────────────
def load_lines(filepath: str) -> list[str]:
    """Reads a file and returns non-blank, non-comment lines stripped of whitespace."""
    with open(filepath, "r") as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]


def load_scope(filepath: str) -> list[str]:
    """Loads apex domains from a scope file."""
    return load_lines(filepath)


def load_useragents(filepath: str) -> list[str]:
    """Loads user-agent strings from file; returns fallback list if file missing."""
    if not os.path.isfile(filepath):
        return [DEFAULT_UA]
    lines = load_lines(filepath)
    return lines if lines else [DEFAULT_UA]


def in_scope(target: str, scope_domains: list[str]) -> bool:
    """
    Returns True if target belongs to any apex domain in scope_domains.
    Strips protocol and path before checking.
    """
    # Strip protocol
    stripped = target
    for proto in ("https://", "http://"):
        if stripped.startswith(proto):
            stripped = stripped[len(proto):]
            break
    # Strip path/query/fragment — take only the host part
    stripped = stripped.split("/")[0].split("?")[0].split("#")[0].lower()
    for apex in scope_domains:
        apex = apex.strip().lower()
        if stripped == apex or stripped.endswith("." + apex):
            return True
    return False


def filter_scope(targets: list[str], scope_domains: list[str]) -> tuple[list[str], int]:
    """
    Filters targets by scope. Returns (kept, rejected_count).
    If scope_domains is empty, all targets are kept.
    """
    if not scope_domains:
        return targets, 0
    kept = []
    rejected = 0
    for t in targets:
        if in_scope(t, scope_domains):
            kept.append(t)
        else:
            rejected += 1
    return kept, rejected


# ── Subprocess wrappers ─────────────────────────────────────
def run_subfinder(domain: str, delay: float) -> list[str]:
    """Runs subfinder for a single apex domain. Returns list of discovered subdomains."""
    tmp_out = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp_out.close()
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-o", tmp_out.name],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"[WARN] subfinder error: {result.stderr.strip()}", file=sys.stderr)
            return []
        with open(tmp_out.name, "r") as f:
            lines = [l.strip() for l in f if l.strip()]
        return lines
    except Exception as e:
        print(f"[WARN] subfinder error: {e}", file=sys.stderr)
        return []
    finally:
        os.unlink(tmp_out.name)
        time.sleep(delay)


def run_dnsx(domains: list[str], delay: float) -> list[str]:
    """Validates a list of domain strings via dnsx. Returns only those that resolved."""
    if not domains:
        return []

    tmp_in = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp_out = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    try:
        tmp_in.write("\n".join(domains))
        tmp_in.close()
        tmp_out.close()
        result = subprocess.run(
            ["dnsx", "-l", tmp_in.name, "-silent", "-o", tmp_out.name],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"[WARN] dnsx error: {result.stderr.strip()}", file=sys.stderr)
            return []
        with open(tmp_out.name, "r") as f:
            lines = [l.strip() for l in f if l.strip()]
        return lines
    except Exception as e:
        print(f"[WARN] dnsx error: {e}", file=sys.stderr)
        return []
    finally:
        for path in (tmp_in.name, tmp_out.name):
            try:
                os.unlink(path)
            except OSError:
                pass
        time.sleep(delay)


def run_httpx(targets: list[str], user_agent: str, delay: float) -> list[dict]:
    """Probes a list of domains or URLs via httpx. Returns list of result dicts."""
    if not targets:
        return []

    tmp_in = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp_out = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    try:
        tmp_in.write("\n".join(targets))
        tmp_in.close()
        tmp_out.close()
        result = subprocess.run(
            [
                "httpx",
                "-l", tmp_in.name,
                "-silent",
                "-json",
                "-title",
                "-status-code",
                "-server",
                "-location",
                "-content-length",
                "-H", f"User-Agent: {user_agent}",
                "-o", tmp_out.name,
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"[WARN] httpx error: {result.stderr.strip()}", file=sys.stderr)
            return []
        results = []
        with open(tmp_out.name, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    status_code = data.get("status_code")
                    if status_code is None:
                        continue
                    results.append({
                        "url": data.get("url", ""),
                        "status_code": int(status_code),
                        "title": data.get("title") or None,
                        "server": data.get("server") or None,
                        "redirect": data.get("location") or None,
                        "content_length": data.get("content_length") or None,
                    })
                except (json.JSONDecodeError, ValueError):
                    continue
        return results
    except Exception as e:
        print(f"[WARN] httpx error: {e}", file=sys.stderr)
        return []
    finally:
        for path in (tmp_in.name, tmp_out.name):
            try:
                os.unlink(path)
            except OSError:
                pass
        time.sleep(delay)


# ── LLM client ──────────────────────────────────────────────
def build_domain_system_prompt(context: str, candidates: int) -> str:
    context_block = (
        f"\nAdditional context about the target provided by the operator:\n{context}"
        if context
        else ""
    )
    return (
        f"You are a subdomain enumeration assistant supporting an authorized penetration test.\n\n"
        f"Your task is to predict subdomains that likely exist for the target organization,\n"
        f"based on naming patterns observed in the confirmed subdomains provided to you.\n\n"
        f"Output rules — follow these exactly:\n"
        f"- Output ONLY a plain list of subdomains, one per line\n"
        f"- No explanations, no markdown, no bullet points, no numbering, no commentary\n"
        f"- Do not repeat any subdomain already in the confirmed list\n"
        f"- Only output valid subdomain format: label.apex.com\n"
        f"- Do not output bare apex domains\n"
        f"- Do not output URLs with protocols\n"
        f"- Generate exactly {candidates} candidates"
        f"{context_block}"
    )


def build_url_system_prompt(context: str, candidates: int) -> str:
    context_block = (
        f"\nAdditional context about the target provided by the operator:\n{context}"
        if context
        else ""
    )
    return (
        f"You are an endpoint enumeration assistant supporting an authorized penetration test.\n\n"
        f"Your task is to predict URL paths that likely exist on the target application,\n"
        f"based on naming patterns, conventions, and structures observed in the confirmed\n"
        f"URLs provided to you.\n\n"
        f"Output rules — follow these exactly:\n"
        f"- Output ONLY a plain list of full URLs, one per line\n"
        f"- No explanations, no markdown, no bullet points, no numbering, no commentary\n"
        f"- Do not repeat any URL already in the confirmed list\n"
        f"- Preserve the exact base URL, protocol, and hostname from the confirmed list\n"
        f"- Only vary the path component\n"
        f"- Generate exactly {candidates} candidates"
        f"{context_block}"
    )


def build_user_message(confirmed: list[str], mode: str, candidates: int) -> str:
    mode_label = "subdomains" if mode in ("domain", "llm") else "URLs"
    confirmed_list = "\n".join(sorted(confirmed))
    return (
        f"Confirmed {mode_label} discovered so far ({len(confirmed)} total):\n\n"
        f"{confirmed_list}\n\n"
        f"Generate {candidates} new candidates that do not appear in the list above."
    )


def call_llm(
    system_prompt: str,
    user_message: str,
    api_key: str,
    model: str,
    base_url: Optional[str],
    delay: float,
    debug: bool = False,
) -> list[str]:
    """Calls Claude API (or local model). Returns list of candidates parsed from response."""
    try:
        if base_url:
            client = anthropic.Anthropic(api_key=api_key, base_url=base_url)
        else:
            client = anthropic.Anthropic(api_key=api_key)

        response = client.messages.create(
            model=model,
            max_tokens=2048,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        raw = response.content[0].text

        if debug:
            print("[DEBUG] Raw LLM response:")
            print("-" * 40)
            print(raw[:2000])
            if len(raw) > 2000:
                print(f"  ... ({len(raw) - 2000} more chars truncated)")
            print("-" * 40)

        candidates = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                continue
            if " " in line:
                if debug:
                    print(f"[DEBUG] Filtered (contains space): {line!r}")
                continue
            candidates.append(line)
        return candidates
    except Exception as e:
        print(f"[WARN] LLM API error: {e}", file=sys.stderr)
        return []
    finally:
        time.sleep(delay)


# ── Mode orchestrators ──────────────────────────────────────
def run_domain_mode(config: dict) -> dict:
    """Full domain mode pipeline. Returns results dict."""
    seeds = load_lines(config["input"])
    seeds, seed_rejected = filter_scope(seeds, config["scope_domains"])
    print(f"[*] Loaded {len(seeds)} seed domains")
    scope_rejected = seed_rejected

    scope_status = f"enabled ({config['scope_file']})" if config["scope_domains"] else "disabled"
    print(f"[*] Scope: {scope_status}")

    # Passive subdomain enumeration
    print(f"[*] Running subfinder on {len(seeds)} domains...")
    passive_set: set[str] = set()
    for domain in seeds:
        found = run_subfinder(domain, config["delay"])
        kept, rej = filter_scope(found, config["scope_domains"])
        scope_rejected += rej
        passive_set.update(kept)
    print(f"[*] Subfinder found {len(passive_set)} passive subdomains")

    # DNS validation of passive results
    print("[*] Running dnsx validation...")
    confirmed_domains: set[str] = set(run_dnsx(list(passive_set), config["delay"]))
    print(f"[*] DNS confirmed: {len(confirmed_domains)} subdomains")

    alive_hosts: list[dict] = []
    rounds_summary: list[dict] = []
    all_candidates_ever: set[str] = set()

    for round_num in range(1, config["rounds"] + 1):
        print(f"\n[Round {round_num}/{config['rounds']}]")

        system_prompt = build_domain_system_prompt(config["context"], config["candidates"])
        user_message = build_user_message(list(confirmed_domains), "domain", config["candidates"])

        print(f"  [*] Calling LLM (context: {len(confirmed_domains)} confirmed subdomains)...")
        raw_candidates = call_llm(
            system_prompt, user_message,
            config["api_key"], config["model"], config["llm_url"], config["delay"],
            debug=config.get("debug", False),
        )
        print(f"  [*] LLM returned {len(raw_candidates)} candidates")

        if not raw_candidates:
            print("  [WARN] LLM returned no candidates this round.")
            rounds_summary.append({"round": round_num, "llm": 0, "scope_filtered": 0, "dns": 0, "alive": 0})
            continue

        kept, rej = filter_scope(raw_candidates, config["scope_domains"])
        scope_rejected += rej
        print(f"  [*] Scope filtered: {rej}")

        new_candidates = [c for c in kept if c not in confirmed_domains]
        all_candidates_ever.update(new_candidates)
        print(f"  [*] Deduped: {len(new_candidates)} new candidates to validate")

        print("  [*] DNS validation...")
        newly_resolved = run_dnsx(new_candidates, config["delay"])
        print(f"  [+] {len(newly_resolved)} new subdomains resolved")

        if not newly_resolved:
            print("  No new domains resolved this round.")
            rounds_summary.append({"round": round_num, "llm": len(raw_candidates), "scope_filtered": rej, "dns": 0, "alive": 0})
            continue

        confirmed_domains.update(newly_resolved)

        ua = random.choice(config["user_agents"])
        print(f"  [*] HTTP probing {len(newly_resolved)} new subdomains...")
        new_alive = run_httpx(newly_resolved, ua, config["delay"])
        print(f"  [+] {len(new_alive)} alive")
        alive_hosts.extend(new_alive)

        rounds_summary.append({
            "round": round_num,
            "llm": len(raw_candidates),
            "scope_filtered": rej,
            "dns": len(newly_resolved),
            "alive": len(new_alive),
        })

    # Probe any confirmed domains not yet in alive_hosts
    probed_urls = {h["url"] for h in alive_hosts}
    already_probed_domains = set()
    for h in alive_hosts:
        url = h["url"]
        for proto in ("https://", "http://"):
            if url.startswith(proto):
                already_probed_domains.add(url[len(proto):].split("/")[0])
    unprobed = [d for d in confirmed_domains if d not in already_probed_domains]
    if unprobed:
        ua = random.choice(config["user_agents"])
        print(f"\n[*] HTTP probing {len(unprobed)} remaining confirmed subdomains...")
        remaining_alive = run_httpx(unprobed, ua, config["delay"])
        print(f"[+] {len(remaining_alive)} alive")
        alive_hosts.extend(remaining_alive)

    return {
        "mode": "domain",
        "seeds": seeds,
        "passive_domains": list(passive_set),
        "confirmed_domains": list(confirmed_domains),
        "alive_hosts": alive_hosts,
        "all_candidates": list(all_candidates_ever),
        "scope_rejected": scope_rejected,
        "rounds_summary": rounds_summary,
    }


def run_llm_mode(config: dict) -> dict:
    """LLM-only domain mode — skips subfinder, seeds the LLM directly. Returns results dict."""
    seeds = load_lines(config["input"])
    seeds, seed_rejected = filter_scope(seeds, config["scope_domains"])
    print(f"[*] Loaded {len(seeds)} seed domains")
    scope_rejected = seed_rejected

    scope_status = f"enabled ({config['scope_file']})" if config["scope_domains"] else "disabled"
    print(f"[*] Scope: {scope_status}")
    print(f"[*] Skipping subfinder — seeding LLM directly with {len(seeds)} domains")

    confirmed_domains: set[str] = set(seeds)
    alive_hosts: list[dict] = []
    rounds_summary: list[dict] = []
    all_candidates_ever: set[str] = set()

    for round_num in range(1, config["rounds"] + 1):
        print(f"\n[Round {round_num}/{config['rounds']}]")

        system_prompt = build_domain_system_prompt(config["context"], config["candidates"])
        user_message = build_user_message(list(confirmed_domains), "domain", config["candidates"])

        print(f"  [*] Calling LLM (context: {len(confirmed_domains)} confirmed subdomains)...")
        raw_candidates = call_llm(
            system_prompt, user_message,
            config["api_key"], config["model"], config["llm_url"], config["delay"],
            debug=config.get("debug", False),
        )
        print(f"  [*] LLM returned {len(raw_candidates)} candidates")

        if not raw_candidates:
            print("  [WARN] LLM returned no candidates this round.")
            rounds_summary.append({"round": round_num, "llm": 0, "scope_filtered": 0, "dns": 0, "alive": 0})
            continue

        kept, rej = filter_scope(raw_candidates, config["scope_domains"])
        scope_rejected += rej
        print(f"  [*] Scope filtered: {rej}")

        new_candidates = [c for c in kept if c not in confirmed_domains]
        all_candidates_ever.update(new_candidates)
        print(f"  [*] Deduped: {len(new_candidates)} new candidates to validate")

        print("  [*] DNS validation...")
        newly_resolved = run_dnsx(new_candidates, config["delay"])
        print(f"  [+] {len(newly_resolved)} new subdomains resolved")

        if not newly_resolved:
            print("  No new domains resolved this round.")
            rounds_summary.append({"round": round_num, "llm": len(raw_candidates), "scope_filtered": rej, "dns": 0, "alive": 0})
            continue

        confirmed_domains.update(newly_resolved)

        ua = random.choice(config["user_agents"])
        print(f"  [*] HTTP probing {len(newly_resolved)} new subdomains...")
        new_alive = run_httpx(newly_resolved, ua, config["delay"])
        print(f"  [+] {len(new_alive)} alive")
        alive_hosts.extend(new_alive)

        rounds_summary.append({
            "round": round_num,
            "llm": len(raw_candidates),
            "scope_filtered": rej,
            "dns": len(newly_resolved),
            "alive": len(new_alive),
        })

    return {
        "mode": "llm",
        "seeds": seeds,
        "confirmed_domains": list(confirmed_domains),
        "alive_hosts": alive_hosts,
        "all_candidates": list(all_candidates_ever),
        "scope_rejected": scope_rejected,
        "rounds_summary": rounds_summary,
    }


def run_url_mode(config: dict) -> dict:
    """Full URL mode pipeline. Returns results dict."""
    seeds = load_lines(config["input"])
    seeds, seed_rejected = filter_scope(seeds, config["scope_domains"])
    print(f"[*] Loaded {len(seeds)} seed URLs")
    scope_rejected = seed_rejected

    scope_status = f"enabled ({config['scope_file']})" if config["scope_domains"] else "disabled"
    print(f"[*] Scope: {scope_status}")

    confirmed_urls: set[str] = set(seeds)
    alive_hosts: list[dict] = []
    rounds_summary: list[dict] = []

    for round_num in range(1, config["rounds"] + 1):
        print(f"\n[Round {round_num}/{config['rounds']}]")

        system_prompt = build_url_system_prompt(config["context"], config["candidates"])
        user_message = build_user_message(list(confirmed_urls), "url", config["candidates"])

        print(f"  [*] Calling LLM (context: {len(confirmed_urls)} confirmed URLs)...")
        raw_candidates = call_llm(
            system_prompt, user_message,
            config["api_key"], config["model"], config["llm_url"], config["delay"],
            debug=config.get("debug", False),
        )
        print(f"  [*] LLM returned {len(raw_candidates)} candidates")

        if not raw_candidates:
            print("  [WARN] LLM returned no candidates this round.")
            rounds_summary.append({"round": round_num, "llm": 0, "scope_filtered": 0, "alive": 0})
            continue

        kept, rej = filter_scope(raw_candidates, config["scope_domains"])
        scope_rejected += rej
        print(f"  [*] Scope filtered: {rej}")

        new_candidates = [c for c in kept if c not in confirmed_urls]
        print(f"  [*] Deduped: {len(new_candidates)} new candidates to probe")

        ua = random.choice(config["user_agents"])
        new_alive = run_httpx(new_candidates, ua, config["delay"])
        new_alive_urls = {h["url"] for h in new_alive}
        confirmed_urls.update(new_alive_urls)
        alive_hosts.extend(new_alive)

        if not new_alive:
            print("  No new URLs found alive this round.")
        else:
            print(f"  [+] {len(new_alive)} new URLs alive")

        rounds_summary.append({
            "round": round_num,
            "llm": len(raw_candidates),
            "scope_filtered": rej,
            "alive": len(new_alive),
        })

    return {
        "mode": "url",
        "seeds": seeds,
        "confirmed_urls": list(confirmed_urls),
        "alive_hosts": alive_hosts,
        "scope_rejected": scope_rejected,
        "rounds_summary": rounds_summary,
    }


# ── Output writers ──────────────────────────────────────────
def _fmt_alive_line(h: dict) -> str:
    status = str(h["status_code"])
    if h.get("redirect"):
        status = f"{status} -> {h['redirect']}"
    title = h.get("title") or ""
    server = h.get("server") or ""
    cl = f"{h['content_length']} bytes" if h.get("content_length") is not None else ""
    return f"{h['url']} | {status} | {title} | {server} | {cl}"


def write_txt_output(results: dict, config: dict):
    filepath = config["output"] + ".txt"
    date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mode = results["mode"]

    alive_hosts = results["alive_hosts"]
    alive_urls = {h["url"] for h in alive_hosts}

    if mode in ("domain", "llm"):
        confirmed = set(results["confirmed_domains"])
        dns_only = sorted(confirmed - {
            h["url"].replace("https://", "").replace("http://", "").split("/")[0]
            for h in alive_hosts
        })
        candidates_not_resolved = sorted(
            set(results.get("all_candidates", [])) - confirmed
        )
    else:
        confirmed_urls = set(results["confirmed_urls"])
        dns_only = sorted(confirmed_urls - alive_urls)
        candidates_not_resolved = []

    seeds_set = set(results.get("seeds", []))
    llm_alive = [h for h in alive_hosts if
                 h["url"].replace("https://", "").replace("http://", "").split("/")[0] not in seeds_set]

    lines = [
        "# reconai output",
        f"# Mode    : {mode}",
        f"# Input   : {config['input']}",
        f"# Rounds  : {config['rounds']}",
        f"# Model   : {config['model']}",
        f"# Date    : {date_str}",
        "# ============================================================",
        "",
        "## ALIVE (HTTP probe confirmed)",
    ]
    for h in alive_hosts:
        lines.append(_fmt_alive_line(h))

    if mode == "llm":
        lines += ["", "## LLM-DISCOVERED & ALIVE"]
        lines += [_fmt_alive_line(h) for h in llm_alive] if llm_alive else ["(none)"]

    lines += ["", "## CONFIRMED (DNS resolved, not HTTP probed or not alive)"]
    lines += dns_only if dns_only else ["(none)"]

    lines += ["", "## CANDIDATES (LLM generated, not resolved)"]
    lines += candidates_not_resolved if candidates_not_resolved else ["(none)"]

    try:
        with open(filepath, "w") as f:
            f.write("\n".join(lines) + "\n")
        print(f"    {filepath}")
    except OSError as e:
        print(f"[ERROR] Could not write {filepath}: {e}", file=sys.stderr)
        print("\n".join(lines))


def write_html_output(results: dict, config: dict):
    filepath = config["output"] + ".html"
    date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mode = results["mode"]

    alive_hosts = results["alive_hosts"]
    alive_urls = {h["url"] for h in alive_hosts}

    if mode in ("domain", "llm"):
        confirmed = set(results["confirmed_domains"])
        dns_only = sorted(confirmed - {
            h["url"].replace("https://", "").replace("http://", "").split("/")[0]
            for h in alive_hosts
        })
        candidates_not_resolved = sorted(
            set(results.get("all_candidates", [])) - confirmed
        )
    else:
        confirmed_urls = set(results["confirmed_urls"])
        dns_only = sorted(confirmed_urls - alive_urls)
        candidates_not_resolved = []

    seeds_set = set(results.get("seeds", []))
    llm_alive = [h for h in alive_hosts if
                 h["url"].replace("https://", "").replace("http://", "").split("/")[0] not in seeds_set]

    def esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    alive_items = "\n".join(f"  <li>{esc(_fmt_alive_line(h))}</li>" for h in alive_hosts) or "  <li>(none)</li>"
    dns_items = "\n".join(f"  <li>{esc(d)}</li>" for d in dns_only) or "  <li>(none)</li>"
    cand_items = "\n".join(f"  <li>{esc(c)}</li>" for c in candidates_not_resolved) or "  <li>(none)</li>"

    llm_alive_section = ""
    if mode == "llm":
        llm_alive_items = "\n".join(f"  <li>{esc(_fmt_alive_line(h))}</li>" for h in llm_alive) or "  <li>(none)</li>"
        llm_alive_section = f"""
<h2>LLM-Discovered &amp; Alive ({len(llm_alive)})</h2>
<ul>
{llm_alive_items}
</ul>
"""

    html = f"""<!DOCTYPE html>
<html>
<head><title>reconai output — {esc(mode)} — {esc(date_str)}</title></head>
<body>
<h1>reconai output</h1>
<p>Mode: {esc(mode)} | Input: {esc(config['input'])} | Rounds: {config['rounds']} | Date: {esc(date_str)}</p>

<h2>Alive ({len(alive_hosts)})</h2>
<ul>
{alive_items}
</ul>
{llm_alive_section}
<h2>Confirmed — DNS resolved ({len(dns_only)})</h2>
<ul>
{dns_items}
</ul>

<h2>Candidates — not resolved ({len(candidates_not_resolved)})</h2>
<ul>
{cand_items}
</ul>

</body>
</html>
"""
    try:
        with open(filepath, "w") as f:
            f.write(html)
        print(f"    {filepath}")
    except OSError as e:
        print(f"[ERROR] Could not write {filepath}: {e}", file=sys.stderr)


def print_final_summary(results: dict, config: dict):
    sep = "=" * 60
    print(f"\n{sep}")
    print("reconai | COMPLETE")
    print(sep)
    if results["mode"] in ("domain", "llm"):
        print(f"  Total confirmed subdomains : {len(results['confirmed_domains'])}")
        if results["mode"] == "llm":
            new_domains = sorted(set(results["confirmed_domains"]) - set(results["seeds"]))
            print(f"  New domains (not in input) : {len(new_domains)}")
            if new_domains:
                print()
                print("  LLM-discovered & DNS-validated:")
                for d in new_domains:
                    print(f"    + {d}")
    else:
        print(f"  Total confirmed URLs       : {len(results['confirmed_urls'])}")
    print(f"  Total alive (HTTP)         : {len(results['alive_hosts'])}")
    print(f"  Scope rejected             : {results['scope_rejected']}")
    print("  Output files:")


# ── Startup validation ──────────────────────────────────────
def check_binaries(mode: str) -> list[str]:
    """Returns list of missing binary names required for the given mode."""
    missing = []
    for binary in REQUIRED_BINARIES.get(mode, []):
        if shutil.which(binary) is None:
            missing.append(binary)
    return missing


def validate_config(args) -> list[str]:
    """Validates all startup arguments. Returns list of error strings (empty = all good)."""
    errors = []

    # 1. Mode check
    if args.mode not in ("domain", "url", "llm"):
        errors.append(f"[ERROR] --mode must be 'domain', 'url', or 'llm', got: {args.mode!r}")

    # 2. Input file exists
    if not os.path.isfile(args.input):
        errors.append(f"[ERROR] Input file not found: {args.input}")
    else:
        # 3. Input file not empty (after stripping comments/blanks)
        try:
            with open(args.input, "r") as f:
                lines = [
                    l.strip()
                    for l in f
                    if l.strip() and not l.strip().startswith("#")
                ]
            if not lines:
                errors.append(f"[ERROR] Input file is empty (after removing blank lines and comments): {args.input}")
            # Wildcard check — only relevant for domain mode (subfinder will hang on *.domain.com)
            if args.mode == "domain":
                wildcards = [l for l in lines if l.startswith("*")]
                for w in wildcards:
                    errors.append(f"[ERROR] Wildcard entry in input file not supported in domain mode: {w!r} — use the apex domain instead (e.g. 'example.com')")
        except OSError as e:
            errors.append(f"[ERROR] Cannot read input file: {e}")

    # 4. Scope file exists if provided
    if args.scope and not os.path.isfile(args.scope):
        errors.append(f"[ERROR] Scope file not found: {args.scope}")

    # 5. API key
    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        errors.append(
            "[ERROR] No API key found. Pass --api-key or set ANTHROPIC_API_KEY env var."
        )

    # 6. Numeric bounds
    if args.rounds < 1:
        errors.append(f"[ERROR] --rounds must be >= 1, got: {args.rounds}")
    if args.delay < 0:
        errors.append(f"[ERROR] --delay must be >= 0, got: {args.delay}")
    if args.candidates < 1:
        errors.append(f"[ERROR] --candidates must be >= 1, got: {args.candidates}")

    # 7. Binary checks (only if mode is valid)
    if args.mode in ("domain", "url", "llm"):
        missing = check_binaries(args.mode)
        for binary in missing:
            errors.append(
                f"[ERROR] Required tool not found: {binary}. Install from projectdiscovery.io"
            )

    return errors


# ── CLI entrypoint ──────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="reconai",
        description=(
            "reconai — AI-augmented subdomain and endpoint enumeration.\n\n"
            "Uses Claude to iteratively generate and validate subdomains (domain mode)\n"
            "or URL paths (url mode) based on patterns in already-confirmed targets."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "modes:\n"
            "  domain  passive subdomain discovery via subfinder → DNS validation (dnsx)\n"
            "          → AI generation → DNS validation → HTTP probing (httpx)\n"
            "  llm     AI generation only (no subfinder) → DNS validation → HTTP probing\n"
            "          seeds the LLM directly from the input file\n"
            "  url     HTTP probing of seed URLs → AI generation of new paths\n"
            "          → HTTP probing → repeat\n\n"
            "required tools (auto-detected):\n"
            "  domain mode : subfinder, dnsx, httpx  (projectdiscovery.io)\n"
            "  llm mode    : dnsx, httpx\n"
            "  url mode    : httpx\n\n"
            "examples:\n"
            "  reconai --mode domain --input domains.txt\n"
            "  reconai --mode llm    --input domains.txt --rounds 5\n"
            "  reconai --mode domain --input domains.txt --scope scope.txt --rounds 5\n"
            "  reconai --mode url    --input urls.txt    --candidates 100 --output run1\n"
            "  reconai --mode domain --input domains.txt --context 'e-commerce platform'\n\n"
            "api key:\n"
            "  Pass --api-key or set the ANTHROPIC_API_KEY environment variable."
        ),
    )
    parser.add_argument(
        "--mode", required=True,
        metavar="MODE",
        help="enumeration mode: 'domain' (subfinder + AI), 'llm' (AI only, no subfinder), or 'url' (endpoint discovery)",
    )
    parser.add_argument(
        "--input", required=True,
        metavar="FILE",
        help="path to input file — apex domains (domain mode) or seed URLs (url mode), one per line",
    )
    parser.add_argument(
        "--context", default="",
        metavar="TEXT",
        help="free-text description of the target appended to the LLM system prompt (e.g. 'fintech SaaS')",
    )
    parser.add_argument(
        "--rounds", type=int, default=DEFAULT_ROUNDS,
        metavar="N",
        help=f"number of generate → validate → feedback cycles (default: {DEFAULT_ROUNDS})",
    )
    parser.add_argument(
        "--delay", type=float, default=DEFAULT_DELAY,
        metavar="SECS",
        help=f"seconds to sleep between outbound requests (default: {DEFAULT_DELAY})",
    )
    parser.add_argument(
        "--scope", default=None,
        metavar="FILE",
        help="path to scope file — one apex domain per line; out-of-scope results are dropped",
    )
    parser.add_argument(
        "--api-key", default=None, dest="api_key",
        metavar="KEY",
        help="Claude API key (overrides ANTHROPIC_API_KEY env var)",
    )
    parser.add_argument(
        "--llm-url", default=None, dest="llm_url",
        metavar="URL",
        help="custom base URL for the LLM API (e.g. a local proxy or compatible endpoint)",
    )
    parser.add_argument(
        "--model", default=DEFAULT_MODEL,
        metavar="MODEL",
        help=f"Claude model string passed to the API (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--output", default="reconai_output",
        metavar="BASENAME",
        help="base name for output files — .txt and .html are appended (default: reconai_output)",
    )
    parser.add_argument(
        "--candidates", type=int, default=DEFAULT_CANDIDATES,
        metavar="N",
        help=f"number of candidates to request from the LLM per round (default: {DEFAULT_CANDIDATES})",
    )
    parser.add_argument(
        "--debug", action="store_true", default=False,
        help="print raw LLM responses and filtered lines for troubleshooting",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    errors = validate_config(args)
    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        sys.exit(1)

    # Resolve API key
    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY", "")

    # Load scope
    scope_domains = load_scope(args.scope) if args.scope else []

    # Load user agents
    ua_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "useragents.txt")
    user_agents = load_useragents(ua_file)

    config = {
        "mode": args.mode,
        "input": args.input,
        "context": args.context,
        "rounds": args.rounds,
        "delay": args.delay,
        "scope_domains": scope_domains,
        "scope_file": args.scope or "",
        "api_key": api_key,
        "llm_url": args.llm_url,
        "model": args.model,
        "output": args.output,
        "candidates": args.candidates,
        "user_agents": user_agents,
        "debug": args.debug,
    }

    sep = "=" * 60
    print(sep)
    print(f"reconai | mode: {config['mode']} | rounds: {config['rounds']} | delay: {config['delay']}s | model: {config['model']}")
    print(sep)
    print()

    results = None
    try:
        if config["mode"] == "domain":
            results = run_domain_mode(config)
        elif config["mode"] == "llm":
            results = run_llm_mode(config)
        else:
            results = run_url_mode(config)
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Partial results may be written.")

    if results:
        print_final_summary(results, config)
        write_txt_output(results, config)
        write_html_output(results, config)
        print(sep)


if __name__ == "__main__":
    main()
