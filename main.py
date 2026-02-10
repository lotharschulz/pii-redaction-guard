"""
Showcase: Presidio PII Redaction Guard 

Handles both input sanitization (before LLM) and output sweeping (after LLM).
Supports reversible anonymization so the LLM can reason about entities
while real PII never leaves your perimeter.
Key features:
- Custom recognizers for org-specific PII (project codes, employee IDs, etc.)
- Reversible anonymization with mapping for restoring original values
- Final output sweep to catch any PII the LLM may have hallucinated
- Audit logging of all detections (without storing actual PII)
"""

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine, DeanonymizeEngine
from presidio_anonymizer.entities import (
    OperatorConfig,
    OperatorResult,
    RecognizerResult,
)
from typing import Dict, List, Tuple
import json
import hashlib


# Custom recognizers — extend Presidio for domain-specific PII
def build_custom_recognizers() -> List[PatternRecognizer]:
    """Add recognizers for org-specific identifiers."""

    # Example: internal project codes like "PRJ-20241234"
    project_code = PatternRecognizer(
        supported_entity="PROJECT_CODE",
        name="project_code_recognizer",
        patterns=[Pattern("project_code", r"\bPRJ-\d{8}\b", 0.9)],
    )

    # Example: internal employee IDs like "EMP-A12345"
    employee_id = PatternRecognizer(
        supported_entity="EMPLOYEE_ID",
        name="employee_id_recognizer",
        patterns=[Pattern("employee_id", r"\bEMP-[A-Z]\d{5}\b", 0.9)],
    )

    # Example: German tax IDs (Steuer-ID) — 11-digit number
    german_tax_id = PatternRecognizer(
        supported_entity="DE_TAX_ID",
        name="german_tax_id_recognizer",
        patterns=[Pattern("de_tax_id", r"\b\d{11}\b", 0.4)],
        context=["steuer", "tax", "finanzamt", "steuernummer"],
    )

    return [project_code, employee_id, german_tax_id]


# Analyzer setup
def create_analyzer() -> AnalyzerEngine:
    analyzer = AnalyzerEngine()
    for recognizer in build_custom_recognizers():
        analyzer.registry.add_recognizer(recognizer)
    return analyzer


# Reversible anonymization (encrypt-style with mapping)
class ReversibleAnonymizer:
    """
    Replaces PII with deterministic placeholders and keeps a mapping
    so the original values can be restored after the LLM responds.
    """

    def __init__(self):
        self.analyzer = create_analyzer()
        self.anonymizer = AnonymizerEngine()
        self.deanonymize_engine = DeanonymizeEngine()
        self._mapping: Dict[str, str] = {}  # placeholder -> original
        self._reverse: Dict[str, str] = {}  # original -> placeholder
        self._counters: Dict[str, int] = {}

    def _placeholder(self, entity_type: str, original: str) -> str:
        if original in self._reverse:
            return self._reverse[original]
        count = self._counters.get(entity_type, 0) + 1
        self._counters[entity_type] = count
        placeholder = f"<{entity_type}_{count}>"
        self._mapping[placeholder] = original
        self._reverse[original] = placeholder
        return placeholder

    def _deduplicate_results(self, results):
        """Remove overlapping entities, keeping the one with the highest score."""
        if not results:
            return results
        
        # Sort by start position, then by score (descending)
        sorted_results = sorted(results, key=lambda r: (r.start, -r.score))
        
        deduplicated = []
        for result in sorted_results:
            # Check if this result overlaps with any already accepted result
            overlaps = False
            for accepted in deduplicated:
                # Check for overlap
                if not (result.end <= accepted.start or result.start >= accepted.end):
                    overlaps = True
                    break
            
            if not overlaps:
                deduplicated.append(result)
        
        return deduplicated

    def anonymize(
        self,
        text: str,
        language: str = "en",
        score_threshold: float = 0.7,
        entities: List[str] = None,
    ) -> Tuple[str, List[dict]]:
        """
        Analyze and anonymize PII in text.

        Returns:
            (anonymized_text, list of detections for audit logging)
        """
        # Analyze
        results = self.analyzer.analyze(
            text=text,
            language=language,
            score_threshold=score_threshold,
            entities=entities,
        )

        # Deduplicate overlapping entities - keep highest scoring one
        results = self._deduplicate_results(results)

        # Sort by start position ascending to build string from left to right
        results = sorted(results, key=lambda r: r.start)

        anonymized = ""
        last_end = 0
        detections = []

        for result in results:
            # Add text before this entity
            anonymized += text[last_end : result.start]
            
            # Replace entity with placeholder
            original = text[result.start : result.end]
            placeholder = self._placeholder(result.entity_type, original)
            anonymized += placeholder

            # Build audit record (no actual PII stored — just metadata)
            detections.append(
                {
                    "entity_type": result.entity_type,
                    "score": round(result.score, 3),
                    "start": result.start,
                    "end": result.end,
                    "placeholder": placeholder,
                    # Hash of original for audit correlation without storing PII
                    "pii_hash": hashlib.sha256(original.encode()).hexdigest()[:12],
                }
            )

            last_end = result.end

        # Add remaining text after the last entity
        anonymized += text[last_end:]

        return anonymized, detections

    def deanonymize(self, text: str) -> str:
        """Restore original PII values from placeholders."""
        result = text
        for placeholder, original in self._mapping.items():
            result = result.replace(placeholder, original)
        return result

    def get_mapping(self) -> Dict[str, str]:
        """Return current placeholder mapping (for debugging only)."""
        return dict(self._mapping)


# Standalone functions for simple (non-reversible) redaction
def redact_pii(text: str, language: str = "en") -> Tuple[str, List[dict]]:
    """
    Simple one-shot PII redaction (non-reversible).
    Replaces PII with <ENTITY_TYPE> tags.
    """
    analyzer = create_analyzer()
    anonymizer = AnonymizerEngine()

    results = analyzer.analyze(text=text, language=language, score_threshold=0.4)

    anonymized = anonymizer.anonymize(
        text=text,
        analyzer_results=results,
        operators={
            "DEFAULT": OperatorConfig("replace", {"new_value": "<REDACTED>"}),
            "PERSON": OperatorConfig("replace", {"new_value": "<PERSON>"}),
            "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<EMAIL>"}),
            "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "<PHONE>"}),
            "CREDIT_CARD": OperatorConfig("replace", {"new_value": "<CREDIT_CARD>"}),
            "IBAN_CODE": OperatorConfig("replace", {"new_value": "<IBAN>"}),
            "PROJECT_CODE": OperatorConfig("replace", {"new_value": "<PROJECT_CODE>"}),
            "EMPLOYEE_ID": OperatorConfig("replace", {"new_value": "<EMPLOYEE_ID>"}),
            "DE_TAX_ID": OperatorConfig("replace", {"new_value": "<DE_TAX_ID>"}),
        },
    )

    detections = [
        {
            "entity_type": r.entity_type,
            "score": round(r.score, 3),
            "start": r.start,
            "end": r.end,
        }
        for r in results
    ]

    return anonymized.text, detections


# Guard class for pipeline integration
class PresidioGuard:
    """
    Drop-in guard for the LLM pipeline.
    Use process_input() before the LLM and process_output() after.
    """

    def __init__(self, reversible: bool = True, language: str = "en"):
        self.language = language
        self.reversible = reversible
        self._anonymizer = ReversibleAnonymizer() if reversible else None
        self._audit_log: List[dict] = []

    def process_input(self, user_input: str) -> str:
        """Sanitize user input before sending to the LLM."""
        if self.reversible:
            sanitized, detections = self._anonymizer.anonymize(
                user_input, language=self.language
            )
        else:
            sanitized, detections = redact_pii(user_input, language=self.language)

        if detections:
            self._audit_log.append(
                {
                    "stage": "input",
                    "detections_count": len(detections),
                    "entities_found": list(set(d["entity_type"] for d in detections)),
                    "details": detections,
                }
            )
            print(f"  [Presidio Input] Redacted {len(detections)} PII entities: "
                  f"{[d['entity_type'] for d in detections]}")

        return sanitized

    def process_output(self, llm_output: str) -> str:
        """
        Process LLM output:
        - If reversible: restore original PII values
        - Always: run a final PII sweep to catch any PII the LLM may have generated
        """
        # Step 1: Deanonymize if reversible
        if self.reversible and self._anonymizer:
            output = self._anonymizer.deanonymize(llm_output)
        else:
            output = llm_output

        # Step 2: Final sweep — catch any NEW PII the LLM might have hallucinated
        final_clean, final_detections = redact_pii(output, language=self.language)

        if final_detections:
            self._audit_log.append(
                {
                    "stage": "output_sweep",
                    "detections_count": len(final_detections),
                    "entities_found": list(
                        set(d["entity_type"] for d in final_detections)
                    ),
                    "details": final_detections,
                }
            )
            print(f"  [Presidio Output] Caught {len(final_detections)} PII entities in LLM output")

            # In production, decide policy:
            # Option A: Return redacted version (safer)
            return final_clean
            # Option B: Return original and just log (less safe)
            # return output

        return output

    def get_audit_log(self) -> List[dict]:
        return self._audit_log


# Demo / Usage
if __name__ == "__main__":
    print("=" * 70)
    print("Showcase: Presidio PII Guard")
    print("=" * 70)

    guard = PresidioGuard(reversible=True, language="en")

    # Simulate user input with PII
    user_input = (
        "Hi, my name is John Doe and my email is john.doe@example.com. "
        "My phone number is +44 1234567. "
        "I'm working on project PRJ-20241234 and my employee ID is EMP-A12345. "
        "Please review the contract for client XYZ Corp."
    )

    print(f"\n[User Input]\n{user_input}\n")

    # --- INPUT GUARD ---
    sanitized = guard.process_input(user_input)
    print(f"\n[Sanitized for LLM]\n{sanitized}\n")

    # --- Simulate LLM response (using placeholders) ---
    llm_response = (
        f"I've reviewed the details for {sanitized.split('working on ')[1].split(' and')[0]}. "
        f"The contract looks good. I'll send a summary to <EMAIL_ADDRESS_1>."
    )
    print(f"[Simulated LLM Response]\n{llm_response}\n")

    # --- OUTPUT GUARD ---
    final_output = guard.process_output(llm_response)
    print(f"\n[Final Output to User]\n{final_output}\n")

    # --- AUDIT LOG ---
    print("\n[Audit Log]")
    print(json.dumps(guard.get_audit_log(), indent=2))