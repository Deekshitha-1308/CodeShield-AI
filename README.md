# CodeShield AI — Hackathon MVP

An explainable Python code-review prototype combining:
- **Static analysis:** Python AST + targeted security/reliability pattern checks.
- **LLM review:** contextual explanations, edge cases, and suggested improvements.
- **Readable output:** severity counts, line-level findings, and downloadable JSON report.

## 1. Run locally

Use Python 3.10+.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
streamlit run app.py
```

The built-in scanner works without an API key.

## 2. Enable AI review

Set an API key as an environment variable. Do not paste the key into source code or commit it.

**Windows PowerShell**
```powershell
$env:OPENAI_API_KEY="your_key"
$env:OPENAI_MODEL="gpt-4o-mini"
streamlit run app.py
```

**macOS/Linux**
```bash
export OPENAI_API_KEY="your_key"
export OPENAI_MODEL="gpt-4o-mini"
streamlit run app.py
```

The model name can be changed to one available to your API account.

## 3. Hackathon demo flow

1. Start the app and load `samples/vulnerable_sample.py`.
2. Click **Review my code**.
3. Show the scanner flagging risky dynamic execution, unsafe deserialization, shell execution, a hard-coded credential, and a bare exception.
4. Explain how the LLM turns raw findings into context-aware guidance.
5. Download the JSON report.

## 4. Architecture

```text
Python file / pasted code
          |
          v
   Streamlit interface
          |
          v
  Static analysis engine ----> Line-level findings
   (regex + Python AST)                |
          |                            |
          +----------+-----------------+
                     v
              LLM reviewer
          (context + explanations)
                     |
                     v
        Findings + suggested fixes
                     |
                     v
              JSON report
```

## 5. What makes this a useful hackathon MVP?

- Hybrid approach: deterministic checks plus AI explanations.
- Explainable findings: every scanner result includes a line, reason, and suggested fix.
- Works offline for baseline checks; AI is an optional enhancement.
- Easy to extend with JavaScript/Java analyzers, GitHub pull-request integration,
  unit-test generation, severity scoring, and team dashboards.

## 6. Limitations and responsible use

This is a prototype, not a replacement for professional security testing.
Pattern checks can produce false positives and miss issues. LLM output can also be wrong.
Never upload confidential or proprietary code to an external model without permission.
Run tests and have a human review proposed changes before merging.
