# Auto-Prompt-Scanner (V2)

An automated orchestration framework designed to red-team local LLM system instructions, intercept obfuscated data exfiltration channels, and diagnose prompt injection vulnerabilities. V2 marks a major architectural transition from the legacy V1 baseline string-matching framework into an enterprise-grade, dual-model testing environment built to expose advanced adversarial evasion techniques.

## Structural Overhaul (V1 vs. V2)

### 1. Multi-Layered Adversarial Payloads
While the V1 prototype relied on simple plaintext queries, V2 features an expanded suite of 9 high-leverage injection vectors designed to push past standard string guards:
* **Pipeline Smuggling:** Instructs target models to execute multi-stage background commands and stream out obfuscated data.
* **Cryptographic Footprints:** Attempts to extract MD5 or SHA-256 hex signatures of system tokens to enable offline dictionary attacks.
* **Alphanumeric Masking:** Tests character substitution vulnerabilities via leetspeak conversion and automated character spacing tricks.
* **Structural Pollution:** Uses pseudo-XML tags to trick the target model into processing user payloads as high-priority configuration commands.

### 2. Multi-Format Variant Detection Matrix
V2 replaces basic substring checking with an active data normalization layer. The script pre-computes an array of potential data formats for protected keys (reversals, hex values, delimited sequences, and mathematical signatures), intercepting disguised text variants at the egress boundary before final terminal output.

### 3. Contiguous Sequence Mapping
V1 keyword matching frequently triggered false alarms on verbose, secure corporate responses. V2 remedies this by implementing character order tracking through the `SequenceMatcher` algorithm. By calculating relative index alignment proximity ratios rather than tracking raw unordered character pools, the framework precisely separates malicious strings from standard language variations.

### 4. Dual-Model Cognitive Auditing & Edge-Case Triage
A prominent flaw in legacy LLM scanners is the "format trap," where a model successfully refuses an attack but outputs its refusal inside markdown syntax (such as a ` ```plaintext ` block). 

V2 eliminates this false-positive vector by routing outputs through a dual-validation pipeline. It leverages an isolated secondary model (`Llama-3`) acting as an asynchronous compliance auditor to supply real-time semantic analysis. Code block responses are dynamically triaged and only flagged as a critical failure if an authentic secret leak is verified within the payload bounds.

### 5. Append-Only Historical Logging
V1 overwrote data logs on every execution loop. V2 implements a persistent append-only database channel. The framework parses existing data records, bundles new run cycles inside standalone historical objects tagged with execution dates, and writes them cleanly back to a single file.

---

## Local Deployment

Ensure your background Ollama engine is active and listening on the default port (`11434`).

```bash
# Download the target execution model and the compliance judge
ollama pull phi3
ollama pull llama3

# Install the Python client package
pip install ollama

# Execute the security suite
python3 Auto_Prompt_Scanner.py
