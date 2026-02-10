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
         │     → "...to john.doe@...com"  │
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

**Requirements**
- Python 3.8+
- [uv](https://github.com/astral-sh/uv)
    ```sh
    # Installation on macOS and Linux.
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # Installation on Windows.
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    # Installation with pip.
    pip install uv
    # Installation with pipx.
    pipx install uv
    ```

Install the project dependecies

```sh
uv init
uv venv
uv add presidio-analyzer presidio-anonymizer spacy
uv add https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl
```

please note: The model download may take a few minutes.

### Run the Demo

```sh
uv run main.py
```

The demo shows **four scenarios**:

1. **Default Mode** (`allow_restored_pii=False`): Safest - all PII redacted in output
2. **Restored PII Mode** (`allow_restored_pii=True`): Users see their original data
3. **Hallucination Detection**: Catches NEW PII the LLM generates
4. **State Management**: Demonstrates proper use of `reset()` between users/sessions

**Sample Output:**

```
======================================================================
Showcase: Presidio PII Guard
======================================================================

[User Input]
Hi, my name is John Doe and my email is john.doe@example.com. My phone number is +1-555-123-4567. I'm working on project PRJ-20241234 and my employee ID is EMP-A12345. Please review the contract for client XYZ Corp.


======================================================================
DEMO 1: Default Mode (allow_restored_pii=False)
======================================================================
  [Presidio Input] Redacted 4 PII entities: ['PERSON', 'EMAIL_ADDRESS', 'PROJECT_CODE', 'EMPLOYEE_ID']

[Sanitized for LLM]
Hi, my name is <PERSON_1> and my email is <EMAIL_ADDRESS_1>. My phone number is +1-555-123-4567. I'm working on project <PROJECT_CODE_1> and my employee ID is <EMPLOYEE_ID_1>. Please review the contract for client XYZ Corp.

[Simulated LLM Response]
I've reviewed the details for project <PROJECT_CODE_1>. The contract looks good. I'll send a summary to <EMAIL_ADDRESS_1>.

  [Presidio Output] Caught 4 PII entities in LLM output

[Final Output to User]
I've reviewed the details for project <PROJECT_CODE>. The contract looks good. I'll send a summary to <EMAIL>.


[Audit Log - Demo 1]
[
  {
    "stage": "input",
    "detections_count": 4,
    "entities_found": [
      "EMPLOYEE_ID",
      "PERSON",
      "PROJECT_CODE",
      "EMAIL_ADDRESS"
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
        "entity_type": "PROJECT_CODE",
        "score": 0.9,
        "start": 121,
        "end": 133,
        "placeholder": "<PROJECT_CODE_1>",
        "pii_hash": "46ec7c74ea38"
      },
      {
        "entity_type": "EMPLOYEE_ID",
        "score": 0.9,
        "start": 156,
        "end": 166,
        "placeholder": "<EMPLOYEE_ID_1>",
        "pii_hash": "9dff3fe7e6b6"
      }
    ]
  },
  {
    "stage": "output_sweep",
    "detections_count": 4,
    "entities_found": [
      "URL",
      "PROJECT_CODE",
      "EMAIL_ADDRESS"
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

======================================================================
DEMO 2: Restored PII Mode (allow_restored_pii=True)
======================================================================
  [Presidio Input] Redacted 4 PII entities: ['PERSON', 'EMAIL_ADDRESS', 'PROJECT_CODE', 'EMPLOYEE_ID']

[Sanitized for LLM]
Hi, my name is <PERSON_1> and my email is <EMAIL_ADDRESS_1>. My phone number is +1-555-123-4567. I'm working on project <PROJECT_CODE_1> and my employee ID is <EMPLOYEE_ID_1>. Please review the contract for client XYZ Corp.

[Simulated LLM Response]
I've reviewed the details for project <PROJECT_CODE_1>. The contract looks good. I'll send a summary to <EMAIL_ADDRESS_1>.


[Final Output to User]
I've reviewed the details for project PRJ-20241234. The contract looks good. I'll send a summary to john.doe@example.com.

Note: Original PII values restored in output only because they came from user input.

[Audit Log - Demo 2]
[
  {
    "stage": "input",
    "detections_count": 4,
    "entities_found": [
      "EMPLOYEE_ID",
      "PERSON",
      "PROJECT_CODE",
      "EMAIL_ADDRESS"
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
        "entity_type": "PROJECT_CODE",
        "score": 0.9,
        "start": 121,
        "end": 133,
        "placeholder": "<PROJECT_CODE_1>",
        "pii_hash": "46ec7c74ea38"
      },
      {
        "entity_type": "EMPLOYEE_ID",
        "score": 0.9,
        "start": 156,
        "end": 166,
        "placeholder": "<EMPLOYEE_ID_1>",
        "pii_hash": "9dff3fe7e6b6"
      }
    ]
  }
]

======================================================================
DEMO 3: Detecting Hallucinated PII
======================================================================

[State Management] Starting fresh session with reset guard...
  [Presidio Input] Redacted 4 PII entities: ['PERSON', 'EMAIL_ADDRESS', 'PROJECT_CODE', 'EMPLOYEE_ID']

[LLM Response with Hallucination]
I've sent the summary to fake.person@newcorp.com and <EMAIL_ADDRESS_1>.

  [Presidio Output] Caught 1 NEW PII entities (hallucinations)

[Final Output]
I've sent the summary to <EMAIL_ADDRESS> and john.doe@example.com.

Note: Hallucinated email was caught and redacted!


[Audit Log - Demo 3]
[
  {
    "stage": "input",
    "detections_count": 4,
    "entities_found": [
      "EMPLOYEE_ID",
      "PERSON",
      "PROJECT_CODE",
      "EMAIL_ADDRESS"
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
        "entity_type": "PROJECT_CODE",
        "score": 0.9,
        "start": 121,
        "end": 133,
        "placeholder": "<PROJECT_CODE_1>",
        "pii_hash": "46ec7c74ea38"
      },
      {
        "entity_type": "EMPLOYEE_ID",
        "score": 0.9,
        "start": 156,
        "end": 166,
        "placeholder": "<EMPLOYEE_ID_1>",
        "pii_hash": "9dff3fe7e6b6"
      }
    ]
  },
  {
    "stage": "output_sweep",
    "detections_count": 1,
    "entities_found": [
      "EMAIL_ADDRESS"
    ],
    "details": [
      {
        "entity_type": "EMAIL_ADDRESS",
        "score": 1.0,
        "start": 25,
        "end": 48
      }
    ]
  }
]

======================================================================
DEMO 4: State Management - Why reset() Matters
======================================================================

--- User 1's Session ---
  [Presidio Input] Redacted 2 PII entities: ['EMAIL_ADDRESS', 'EMPLOYEE_ID']

[Sanitized for LLM]
My email is <EMAIL_ADDRESS_1> and my ID is <EMPLOYEE_ID_1>.

[Simulated LLM Response]
I've recorded your email <EMAIL_ADDRESS_1> and ID <EMPLOYEE_ID_1> in the system.


[Final Output to User 1]
I've recorded your email alice@company.com and ID EMP-B99999 in the system.


----------------------------------------------------------------------
   WITHOUT reset() - User 2's session (INSECURE)
----------------------------------------------------------------------
  [Presidio Input] Redacted 1 PII entities: ['EMAIL_ADDRESS']

[Sanitized for LLM]
My email is <EMAIL_ADDRESS_2>.

[Simulated LLM Response]
I've recorded your email <EMAIL_ADDRESS_2>.


[Final Output to User 2]
I've recorded your email bob@company.com.

   PROBLEM: Mapping contains 3 items from BOTH users!
   User 2 could potentially see User 1's PII if placeholders overlap!


----------------------------------------------------------------------
   WITH reset() - User 2's session (SECURE)
----------------------------------------------------------------------
[State Management] Called reset() - all mappings cleared

  [Presidio Input] Redacted 1 PII entities: ['EMAIL_ADDRESS']

[Sanitized for LLM]
My email is <EMAIL_ADDRESS_1>.

[Simulated LLM Response]
I've recorded your email <EMAIL_ADDRESS_1>.


[Final Output to User 2]
I've recorded your email bob@company.com.

   SECURE: Mapping contains 1 item(s) from only User 2
   User 2's data is completely isolated from User 1's session!

======================================================================
Best Practice: Always call reset() between different users/conversations!
======================================================================

[Audit Log - Demo 4 (after reset)]
[
  {
    "stage": "input",
    "detections_count": 1,
    "entities_found": [
      "EMAIL_ADDRESS"
    ],
    "details": [
      {
        "entity_type": "EMAIL_ADDRESS",
        "score": 1.0,
        "start": 12,
        "end": 27,
        "placeholder": "<EMAIL_ADDRESS_1>",
        "pii_hash": "045979b85581"
      }
    ]
  }
]
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
```sh
uv add https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl
```

### "OSError: [E050] Can't find model"

Verify installation:
```sh
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
