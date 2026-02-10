# Showcase: Presidio PII Redaction Guard

**Protect sensitive data when using LLMs** — redacts PII before LLM processing and sweeps output to catch any leaked or hallucinated data.

Uses [Microsoft Presidio](https://microsoft.github.io/presidio/) for PII detection and anonymization.

## Why This Matters

When integrating LLMs into applications handling sensitive data (healthcare, finance, HR, legal), you may face challenges:

- **Data Leakage**: User input may contain PII that shouldn't be sent to external LLMs
- **Compliance**: GDPR, HIPAA, and other regulations require strict PII handling
- **Audit Requirements**: Organizations need logs of what PII was processed

This guard provides a **defense-in-depth approach**: sanitize inputs AND sweep outputs.

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│ User Input: "My email is john.doe@example.com"                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
                    [INPUT SANITIZATION]
                    Detect & anonymize PII
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ To LLM: "My email is <EMAIL_ADDRESS_1>"                         │
└─────────────────────────────────────────────────────────────────┘
                              ↓
                    [LLM PROCESSING]
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ LLM Response: "I'll send a summary to <EMAIL_ADDRESS_1>"        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
                    [OUTPUT SWEEP]
                    Catch any new/leaked PII
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ To User: "I'll send a summary to <EMAIL>"                       │
└─────────────────────────────────────────────────────────────────┘
```

## Features

- **Dual Protection**: Input sanitization + output sweeping
- **Anonymization for LLM reasoning**: LLM sees placeholders only, also identified PII data are not leaked in output.
- **Custom Recognizers**: Extend detection for org-specific patterns (project codes, employee IDs, etc.)
- **Built-in Detectors**: Email, phone, credit card, IBAN, names, locations, and more
- **Audit Logging**: Track all detections with hashed PII (not actual values) for compliance
- **Multi-Language**: Supports additional languages via spaCy models

## Quick Start

### Installation

**Requirements**: Python 3.8+

```bash
# Using uv (recommended)
uv add presidio-analyzer presidio-anonymizer spacy
uv add https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl
```

please note: The used model download may take a few minutes.

### Run the Demo

```bash
uv run main.py
```

**Expected Output**:

```
======================================================================
Showcase: Presidio PII Guard
======================================================================

[User Input]
Hi, my name is John Doe and my email is john.doe@example.com. My phone number is +44 1234567. I'm working on project PRJ-20241234 and my employee ID is EMP-A12345. Please review the contract for client XYZ Corp.

  [Presidio Input] Redacted 5 PII entities: ['PERSON', 'EMAIL_ADDRESS', 'DATE_TIME', 'PROJECT_CODE', 'EMPLOYEE_ID']

[Sanitized for LLM]
Hi, my name is <PERSON_1> and my email is <EMAIL_ADDRESS_1>. My phone number is <DATE_TIME_1>. I'm working on project <PROJECT_CODE_1> and my employee ID is <EMPLOYEE_ID_1>. Please review the contract for client XYZ Corp.

[Simulated LLM Response]
I've reviewed the details for project <PROJECT_CODE_1>. The contract looks good. I'll send a summary to <EMAIL_ADDRESS_1>.

  [Presidio Output] Caught 4 PII entities in LLM output

[Final Output to User]
I've reviewed the details for project <PROJECT_CODE>. The contract looks good. I'll send a summary to <EMAIL>.


[Audit Log]
[
  {
    "stage": "input",
    "detections_count": 5,
    "entities_found": [
      "PERSON",
      "EMAIL_ADDRESS",
      "PROJECT_CODE",
      "EMPLOYEE_ID",
      "DATE_TIME"
    ],
    "details": [
      {
        "entity_type": "PERSON",
        "score": 0.85,
        "start": 15,
        "end": 23,
        "placeholder": "<PERSON_1>",
        "pii_hash": "6cea57c2fb6c"
      },
      {
        "entity_type": "EMAIL_ADDRESS",
        "score": 1.0,
        "start": 40,
        "end": 60,
        "placeholder": "<EMAIL_ADDRESS_1>",
        "pii_hash": "836f82db9912"
      },
      {
        "entity_type": "DATE_TIME",
        "score": 0.85,
        "start": 81,
        "end": 92,
        "placeholder": "<DATE_TIME_1>",
        "pii_hash": "eb3b54730a61"
      },
      {
        "entity_type": "PROJECT_CODE",
        "score": 0.9,
        "start": 117,
        "end": 129,
        "placeholder": "<PROJECT_CODE_1>",
        "pii_hash": "46ec7c74ea38"
      },
      {
        "entity_type": "EMPLOYEE_ID",
        "score": 0.9,
        "start": 152,
        "end": 162,
        "placeholder": "<EMPLOYEE_ID_1>",
        "pii_hash": "9dff3fe7e6b6"
      }
    ]
  },
  {
    "stage": "output_sweep",
    "detections_count": 4,
    "entities_found": [
      "EMAIL_ADDRESS",
      "URL",
      "PROJECT_CODE"
    ],
    "details": [
      {
        "entity_type": "EMAIL_ADDRESS",
        "score": 1.0,
        "start": 100,
        "end": 120
      },
      {
        "entity_type": "PROJECT_CODE",
        "score": 0.9,
        "start": 38,
        "end": 50
      },
      {
        "entity_type": "URL",
        "score": 0.5,
        "start": 100,
        "end": 107
      },
      {
        "entity_type": "URL",
        "score": 0.5,
        "start": 109,
        "end": 120
      }
    ]
  }
]
```

## Troubleshooting

### "No module named 'en_core_web_lg'"

The spaCy model isn't installed. Run:
```bash
uv add https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl
```

### "OSError: [E050] Can't find model"

Verify installation:
```bash
python -c "import spacy; nlp = spacy.load('en_core_web_lg'); print('✓ Model loaded')"
```

### Low Detection Accuracy

- Lower `score_threshold` (e.g., 0.6) to catch more entities
- Add context keywords to custom recognizers
- Use a larger spaCy model (already using `lg` in this demo)

### High False Positives

- Raise `score_threshold` (e.g., 0.8)
- Add negative patterns or allowlists
- Review and remove overly broad custom recognizers

## Multi-Language Support

```python
# please note: I did not test this and share this based on my docs understanding

# Install German model first:
uv add https://github.com/explosion/spacy-models/releases/download/de_core_news_lg-3.8.0/de_core_news_lg-3.8.0-py3-none-any.whl

# German text
guard_de = PresidioGuard(reversible=True, language="de")
```

See [Presidio language support](https://microsoft.github.io/presidio/analyzer/languages/) for details.

## Resources

- [Microsoft Presidio Documentation](https://microsoft.github.io/presidio/)
- [spaCy Models](https://spacy.io/models)
