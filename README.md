# Chrome extension static security checker

## Setup

From this folder:

```powershell
py -m pip install -r requirements.txt
```

## Run

```powershell
py main.py "C:\path\to\unpacked_extension" --output report.json
py main.py "C:\path\to\extension.zip" --output report.json
```

To include package metadata and optionally public Chrome Web Store listing information:

```powershell
py main.py extension.zip --store eimadpbcbfnmbkopoojfekhnkhdbieeh --output report.json
py main.py extension.zip --store eimadpbcbfnmbkopoojfekhnkhdbieeh --online --output report.json
```

Without `--store`, metadata analysis is skipped. With `--store` but without `--online`, the metadata analyzer checks the local package only; the store listing is not fetched. `--online` requires `--store`.

## Components

- `manifestanalyzer.py`: manifest declarations and validation.
- `manifestruleengine.py`: manifest review indicators.
- `access_analyzer.py`: JS Chrome API and DOM access evidence.
- `access_report.py`: permission declaration versus observed API calls.
- `access_rules.py`: access review indicators.
- `network_analyzer.py`: JS network calls, data-to-network heuristics, dynamic code and obfuscation.
- `metadata_analyzer.py`: package integrity metadata and store listing (when enabled).
- `metadata_rules.py`: metadata and manifest/metadata cross-check rules.
- `manifest_parser.py`: adapter needed by the original access report.
- `main.py`: combines results into one JSON report and records component failures.

## Important limitations

This is a **prototype static analyzer**, not a malware verdict. Esprima can fail on newer JavaScript syntax, causing partial results. Network data-flow analysis is heuristic and may produce false positives or miss indirect flows. Package hash comparisons in the metadata analyzer do **not** cryptographically verify signatures.

Untrusted extension source is never executed, but the code is still read and parsed. Scan within an isolated environment for high-risk inputs. ZIP extraction has size and path restrictions; uncompressed folders do not yet have equivalent size limits.

## Human-readable security report and optional AI explanation

The same `main.py` produces **three files by default**:

- `security_report.json`: complete original analyzer output plus a deterministic `risk_assessment`.
- `narrative_report.json`: structured explanation and findings.
- `security_report.html`: readable, self-contained HTML report; open in a browser.

### Run without an API key (free, offline narrative)

```powershell
py main.py "C:\path\to\extension.zip" --output report.json --html report.html
```

This performs the existing static checks, scores the findings using `risk_scorer.py`, and writes a **local deterministic** HTML narrative. No LLM API is contacted. Network access for metadata still requires `--online` and `--store`.

### Run with an OpenAI-generated explanation

First obtain an OpenAI API key and set it in your shell (do **not** put it in source code or commit it):

```powershell
$env:OPENAI_API_KEY = "YOUR_API_KEY"
py main.py "C:\path\to\extension.zip" --llm --model gpt-4.1-mini --output report.json --html report.html
```

For Command Prompt, use `set OPENAI_API_KEY=YOUR_API_KEY` instead. The OpenAI API is billed separately from ChatGPT subscriptions. `--llm` sends **the complete structured report JSON** to OpenAI, including code snippets, extension names, metadata, URLs, and any analyzer errors. Only use it when you are comfortable sharing those details; avoid scanning extensions containing private data. The extension's source code itself is not uploaded wholesale, but truncated snippets included in the JSON are sent.

The model is instructed to explain only supplied evidence and to preserve the Python-generated risk score. If the API is unavailable, the application prints a warning and produces a local fallback report. The report uses HTML escaping to avoid interpreting extension strings or model prose as HTML.

### Additional options

```powershell
py main.py extension.zip --store eimadpbcbfnmbkopoojfekhnkhdbieeh --online --llm --output report.json --html report.html --narrative-output narrative.json
```

- `--llm`: opt in to sending the full JSON analysis to OpenAI for an AI-written narrative.
- `--model`: choose an available OpenAI model (default `gpt-4.1-mini`).
- `--html`: choose the HTML report filename (default `security_report.html`).
- `--narrative-output`: choose the structured narrative filename (default `narrative_report.json`).

### How the rating works

`risk_scorer.py` assigns fixed weights to unique review-indicator types and certain network patterns. It caps the score at 100 and labels it low (0–19), moderate (20–44), elevated (45–69), or high (70–100). These are **review-priority bands**, not calibrated malware probabilities or security certifications. Missing/failed analysis lowers confidence, not the numerical score; check `analysis_status` and the errors list. The LLM cannot change the computed score. The scoring policy is an initial heuristic and should be validated against labeled examples before relying on it for decisions.

### Important caveats

- A static finding does not prove that a network request executed or that sensitive data was exfiltrated.
- Esprima may not parse modern JS; partial scans should be interpreted cautiously.
- The LLM can misinterpret findings despite strict instructions; use the original JSON as ground truth.
- The HTML report contains only a selected explanation of findings; the original JSON preserves all raw analyzer output.
