# Showcase: Presidio PII Redaction Guard

**Protect sensitive data when using LLMs** — redacts PII before LLM processing and sweeps output to catch leaked or hallucinated data.

## Why This Matters

When integrating LLMs into applications handling sensitive data (healthcare, finance, HR, legal), you may face challenges:

- **Data Leakage**: User input may contain PII that shouldn't be sent to external LLMs
- **Compliance**: GDPR, HIPAA, and other regulations require strict PII handling
- **Audit Requirements**: Organizations need logs of what PII was processed

This guard provides a **defense-in-depth approach**: sanitize inputs AND sweep outputs.

## How It Works

### Architecture Flow

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
           [DEANONYMIZATION] (if reversible=True)
           Restore: <EMAIL_ADDRESS_1> → john.doe@example.com
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Deanonymized: "I'll send a summary to john.doe@example.com"     │
└─────────────────────────────────────────────────────────────────┘
                              ↓
              [OUTPUT SWEEP] (if enabled)
              Check for PII in output
                              ↓
         ┌────────────────────────────────┐
         │  Two policies available:       │
         │                                │
         │  A) allow_restored_pii=False   │
         │     Re-redact everything       │
         │     → "...to <EMAIL>"          │
         │                                │
         │  B) allow_restored_pii=True    │
         │     Keep known PII, redact new │
         │     → "...to john.doe@...com" │
         └────────────────────────────────┘
```

### Understanding Reversible Mode

**Reversible mode** maintains a mapping between placeholders and original values:
- `<EMAIL_ADDRESS_1>` ↔ `john.doe@example.com`
- `<PERSON_1>` ↔ `John Doe`

This allows the LLM to:
✅ Reason about entities using consistent references  
✅ Process requests without seeing actual PII  
✅ Return responses that reference the same entities

**After the LLM responds**, you can:
- **Restore original values** so users see their real data
- **Sweep for new PII** to catch anything the LLM hallucinated
- **Choose your policy**: Allow restored PII or re-redact everything

## Features

- ✅ **Input Sanitization**: Removes PII before sending to LLM
- ✅ **Reversible Anonymization**: Maintains mappings to restore original values
- ✅ **Output Restoration**: Optionally restore user's PII in final output
- ✅ **Hallucination Detection**: Catches NEW PII the LLM might generate
- ✅ **Flexibility**: Choose between safety (re-redact all) or usability (show restored PII)
- ✅ **Custom Recognizers**: Extend detection for org-specific patterns (project codes, employee IDs)
- ✅ **Built-in Detectors**: Email, phone, credit card, IBAN, names, locations, and more
- ✅ **Audit Logging**: Track all detections with hashed PII (not actual values) for compliance
- ✅ **State Management**: Reset method for new conversations
- ✅ **Multi-Language**: Supports additional languages via spaCy models

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

The demo shows **four scenarios**:

1. **Default Mode** (`allow_restored_pii=False`): Safest - all PII redacted in output
2. **Restored PII Mode** (`allow_restored_pii=True`): Users see their original data
3. **Hallucination Detection**: Catches NEW PII the LLM generates
4. **State Management**: Demonstrates proper use of `reset()` between users/sessions

**Sample Output:**

```
TODO
```

## Configuration

### Basic Usage

```python
from main import PresidioGuard

# Default: Safest mode - no PII in output
guard = PresidioGuard()

# Allow users to see their original data
guard = PresidioGuard(allow_restored_pii=True)

# Disable output sweep entirely (not recommended)
guard = PresidioGuard(sweep_for_hallucinations=False)
```

### All Configuration Options

```python
guard = PresidioGuard(
    reversible=True,                    # Maintain PII mappings
    language="en",                      # Language for detection
    input_threshold=0.7,                # Input detection confidence (0.0-1.0)
    output_threshold=0.7,               # Output detection confidence
    allow_restored_pii=False,           # Allow original PII in output
    sweep_for_hallucinations=True,      # Check output for new PII
)
```

### Parameter Guide

| Parameter | Default | Description |
|-----------|---------|-------------|
| `reversible` | `True` | Maintain mappings between placeholders and original values |
| `language` | `"en"` | Language code for spaCy model |
| `input_threshold` | `0.7` | Confidence threshold for input detection (higher = fewer false positives) |
| `output_threshold` | `0.7` | Confidence threshold for output sweep |
| `allow_restored_pii` | `False` | If `True`, allows known PII in output; if `False`, re-redacts everything |
| `sweep_for_hallucinations` | `True` | Check LLM output for PII |

### Use Case Recommendations

**Maximum Security** (external LLM, compliance-critical):
```python
guard = PresidioGuard(
    allow_restored_pii=False,
    input_threshold=0.6,  # Catch more PII
)
```

**Good User Experience** (internal tools, manageable risk):
```python
guard = PresidioGuard(
    allow_restored_pii=True,
    sweep_for_hallucinations=True,  # Still catch hallucinations
)
```

**Local Models** (no external API):
```python
guard = PresidioGuard(
    allow_restored_pii=True,
    sweep_for_hallucinations=False,  # Trust your local model
)
```

### State Management

```python
guard = PresidioGuard()

# Process conversation 1
guard.process_input("My email is john@example.com")
# ... LLM interaction ...

# Clear state before conversation 2
guard.reset()

# Process conversation 2
guard.process_input("My email is jane@example.com")
```

**Important note**: Always call `reset()` between users or conversations to prevent PII leakage.

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

- Lower `input_threshold` (e.g., 0.5) to catch more entities
- Add context keywords to custom recognizers
- Use a larger spaCy model (already using `lg` in this demo)

### High False Positives

- Raise `input_threshold` (e.g., 0.8)
- Add negative patterns or allowlists
- Review and remove overly broad custom recognizers

### Phone Numbers Detected as DATE_TIME

Short phone numbers like `+44 1234567` may be misclassified. Solutions:
- Use properly formatted numbers: `+1-555-123-4567`
- Add custom PHONE_NUMBER recognizer with stricter patterns
- Filter out DATE_TIME detections with low confidence

### Output Still Showing Placeholders

If you see `<EMAIL>` instead of `john@example.com`:
- Set `allow_restored_pii=True`
- Or disable output sweep: `sweep_for_hallucinations=False`

### Memory/State Issues

- Call `guard.reset()` between conversations
- Don't reuse guard instances across users
- Monitor `_mapping` size in long-running applications

## Multi-Language Support

Please see [Presidio language support](https://microsoft.github.io/presidio/analyzer/languages/) for details.

```python
# please note: I did not test the code below and share this based on my documentation understanding

# Install German model first:
uv add https://github.com/explosion/spacy-models/releases/download/de_core_news_lg-3.8.0/de_core_news_lg-3.8.0-py3-none-any.whl

# German text
guard_de = PresidioGuard(reversible=True, language="de")
```

## Resources

- [Microsoft Presidio Documentation](https://microsoft.github.io/presidio/)
- [spaCy Models](https://spacy.io/models)
