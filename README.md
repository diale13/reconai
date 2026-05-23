# reconai

AI-augmented subdomain and endpoint enumeration. Uses Claude to iteratively generate and validate new targets based on patterns observed in already-confirmed results.

## How it works

**Domain mode** — passive subdomain discovery → DNS validation → AI generates new candidates → DNS validation → HTTP probing → repeat
**URL mode** — HTTP probe seed URLs → AI generates new path candidates → HTTP probe → repeat

---

## Installation

### 1. Python dependencies

```bash
pip install -r requirements.txt
```

Requires Python 3.9+.

### 2. External tools

Install the [ProjectDiscovery](https://projectdiscovery.io) toolkit. All three are available via their installer script or individual Go installs:

```bash
# macOS (Homebrew)
brew install subfinder dnsx httpx

# or via Go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

| Tool | Required for |
|------|-------------|
| `subfinder` | domain mode only |
| `dnsx` | domain mode only |
| `httpx` | both modes |

### 3. API key

Get a Claude API key from [console.anthropic.com](https://console.anthropic.com) and export it:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

Or pass it directly with `--api-key` on each run.

---

## Usage

```
python3 reconai.py --mode <domain|url> --input <file> [options]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | *(required)* | `domain` or `url` |
| `--input` | *(required)* | Input file — apex domains (domain mode) or seed URLs (url mode) |
| `--rounds` | `3` | Number of generate → validate → feedback cycles |
| `--candidates` | `50` | Candidates to request from the LLM per round |
| `--scope` | — | Scope file — one apex domain per line; out-of-scope results are dropped |
| `--context` | — | Free-text description of the target appended to the LLM prompt |
| `--output` | `reconai_output` | Base name for output files (`.txt` and `.html` appended) |
| `--delay` | `1.0` | Seconds to sleep between outbound requests |
| `--model` | `claude-sonnet-4-6` | Claude model string |
| `--api-key` | — | Claude API key (overrides `ANTHROPIC_API_KEY`) |
| `--llm-url` | — | Custom base URL for the LLM API (local proxy / compatible endpoint) |
| `--debug` | off | Print raw LLM responses and filtered lines |

---

## Examples

### Domain mode — basic

Create an input file with one or more apex domains:

```
# domains.txt
example.com
```

Run:

```bash
python3 reconai.py --mode domain --input domains.txt
```

### Domain mode — with scope enforcement and more rounds

```bash
python3 reconai.py \
  --mode domain \
  --input domains.txt \
  --scope scope.txt \
  --rounds 5 \
  --candidates 100 \
  --output results/run1
```

`scope.txt` lists the apex domains that are in-scope. Any candidate outside that list is silently dropped before DNS validation.

### Domain mode — with target context

Providing context about the target helps the LLM generate more relevant candidates:

```bash
python3 reconai.py \
  --mode domain \
  --input domains.txt \
  --context "fintech SaaS platform, uses AWS, internal tooling on *.internal subdomain"
```

### URL mode — endpoint discovery

Create a seed file with known live URLs on the target:

```
# urls.txt
https://example.com/api/v1/users
https://example.com/api/v1/products
https://example.com/admin/dashboard
```

Run:

```bash
python3 reconai.py --mode url --input urls.txt --rounds 3 --candidates 80
```

### Debugging LLM output

If the LLM appears to return no candidates, use `--debug` to inspect the raw response:

```bash
python3 reconai.py --mode domain --input domains.txt --rounds 1 --debug
```

---

## Output

Each run writes two files:

| File | Contents |
|------|----------|
| `<output>.txt` | Plain-text report with alive hosts, DNS-confirmed domains, and unresolved LLM candidates |
| `<output>.html` | Same report in HTML |

**Alive** hosts include HTTP status code, page title, server header, redirect target, and content length.

---

## Input file format

Lines starting with `#` and blank lines are ignored in all input files.

```
# This is a comment
example.com
another-target.com
```
