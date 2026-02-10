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
    # not used below by purpose because input may contain dates that match this pattern
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
    
    Args:
        reversible: If True, maintains mapping to restore original PII values
        language: Language code for PII detection (e.g., 'en', 'de')
        input_threshold: Confidence threshold for input detection (0.0-1.0)
        output_threshold: Confidence threshold for output sweep (0.0-1.0)
        allow_restored_pii: If True, allows restored PII in output (Option B)
        sweep_for_hallucinations: If True, runs output sweep to catch new PII
    """

    def __init__(
        self,
        reversible: bool = True,
        language: str = "en",
        input_threshold: float = 0.7,
        output_threshold: float = 0.7,
        allow_restored_pii: bool = False,
        sweep_for_hallucinations: bool = True,
    ):
        self.language = language
        self.reversible = reversible
        self.input_threshold = input_threshold
        self.output_threshold = output_threshold
        self.allow_restored_pii = allow_restored_pii
        self.sweep_for_hallucinations = sweep_for_hallucinations
        self._anonymizer = ReversibleAnonymizer() if reversible else None
        self._audit_log: List[dict] = []

    def process_input(self, user_input: str) -> str:
        """Sanitize user input before sending to the LLM."""
        if self.reversible:
            sanitized, detections = self._anonymizer.anonymize(
                user_input, language=self.language, score_threshold=self.input_threshold
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
        - Optionally: run a final PII sweep to catch any PII the LLM may have generated
        """
        # Step 1: Deanonymize if reversible
        if self.reversible and self._anonymizer:
            output = self._anonymizer.deanonymize(llm_output)
        else:
            output = llm_output

        # Step 2: Final sweep — catch any NEW PII the LLM might have hallucinated
        if not self.sweep_for_hallucinations:
            return output

        final_clean, final_detections = redact_pii(output, language=self.language)

        if final_detections:
            # Filter detections if we're allowing restored PII
            if self.allow_restored_pii and self.reversible and self._anonymizer:
                # Only count NEW PII (not in our mapping)
                known_values = set(self._anonymizer._mapping.values())
                
                # First, identify which detections are actually NEW
                # Also need to handle overlapping detections (e.g., email detected as URL too)
                new_detections = []
                known_ranges = []  # Track ranges of known PII to skip overlaps
                
                for detection in final_detections:
                    detected_text = output[detection["start"]:detection["end"]]
                    is_known = detected_text in known_values
                    
                    if is_known:
                        # Track this range so overlapping detections can be skipped
                        known_ranges.append((detection["start"], detection["end"]))
                    else:
                        # Check if this detection overlaps with any known PII
                        overlaps_known = False
                        for known_start, known_end in known_ranges:
                            # Check for overlap
                            if not (detection["end"] <= known_start or detection["start"] >= known_end):
                                overlaps_known = True
                                break
                        
                        if not overlaps_known:
                            new_detections.append(detection)
                
                if new_detections:
                    # Deduplicate overlapping new detections (e.g., email detected as both EMAIL and URL)
                    deduplicated_new = []
                    for detection in sorted(new_detections, key=lambda d: (d["start"], -d["score"])):
                        overlaps = False
                        for accepted in deduplicated_new:
                            if not (detection["end"] <= accepted["start"] or detection["start"] >= accepted["end"]):
                                overlaps = True
                                break
                        if not overlaps:
                            deduplicated_new.append(detection)
                    
                    self._audit_log.append(
                        {
                            "stage": "output_sweep",
                            "detections_count": len(deduplicated_new),
                            "entities_found": list(
                                set(d["entity_type"] for d in deduplicated_new)
                            ),
                            "details": deduplicated_new,
                        }
                    )
                    print(f"  [Presidio Output] Caught {len(deduplicated_new)} NEW PII entities (hallucinations)")
                    
                    # Redact only NEW PII, keep known PII
                    result = output
                    # Sort by start position descending to avoid index shifting
                    for detection in sorted(deduplicated_new, key=lambda d: d["start"], reverse=True):
                        entity_type = detection["entity_type"]
                        start = detection["start"]
                        end = detection["end"]
                        result = result[:start] + f"<{entity_type}>" + result[end:]
                    return result
                
                # No new PII - return with restored values
                return output
            else:
                # Default behavior: redact everything detected
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
                return final_clean

        return output

    def get_audit_log(self) -> List[dict]:
        return self._audit_log

    def reset(self):
        """Clear state for new conversation/session."""
        self._audit_log.clear()
        if self._anonymizer:
            self._anonymizer._mapping.clear()
            self._anonymizer._reverse.clear()
            self._anonymizer._counters.clear()


# Demo / Usage
if __name__ == "__main__":
    print("=" * 70)
    print("Showcase: Presidio PII Guard")
    print("=" * 70)

    # Simulate user input with PII
    user_input = (
        "Hi, my name is John Doe and my email is john.doe@example.com. "
        "My phone number is +1-555-123-4567. "
        "I'm working on project PRJ-20241234 and my employee ID is EMP-A12345. "
        "Please review the contract for client XYZ Corp."
    )

    print(f"\n[User Input]\n{user_input}\n")

    # ========================================================================
    # DEMO 1: Default Mode (PII never appears in output - safest)
    # ========================================================================
    print("\n" + "=" * 70)
    print("DEMO 1: Default Mode (allow_restored_pii=False)")
    print("=" * 70)
    
    guard1 = PresidioGuard(reversible=True, allow_restored_pii=False)

    # --- INPUT GUARD ---
    sanitized1 = guard1.process_input(user_input)
    print(f"\n[Sanitized for LLM]\n{sanitized1}\n")

    # --- Simulate LLM response (using placeholders) ---
    llm_response1 = (
        f"I've reviewed the details for {sanitized1.split('working on ')[1].split(' and')[0]}. "
        f"The contract looks good. I'll send a summary to <EMAIL_ADDRESS_1>."
    )
    print(f"[Simulated LLM Response]\n{llm_response1}\n")

    # --- OUTPUT GUARD ---
    final_output1 = guard1.process_output(llm_response1)
    print(f"\n[Final Output to User]\n{final_output1}\n")

    # --- AUDIT LOG ---
    print("\n[Audit Log - Demo 1]")
    print(json.dumps(guard1.get_audit_log(), indent=2))

    # ========================================================================
    # DEMO 2: Allow Restored PII (users see their original data)
    # ========================================================================
    print("\n" + "=" * 70)
    print("DEMO 2: Restored PII Mode (allow_restored_pii=True)")
    print("=" * 70)
    
    # Create new guard OR reset existing one for new conversation
    guard2 = PresidioGuard(reversible=True, allow_restored_pii=True)

    # --- INPUT GUARD ---
    sanitized2 = guard2.process_input(user_input)
    print(f"\n[Sanitized for LLM]\n{sanitized2}\n")

    # --- Simulate LLM response (using placeholders) ---
    llm_response2 = (
        f"I've reviewed the details for {sanitized2.split('working on ')[1].split(' and')[0]}. "
        f"The contract looks good. I'll send a summary to <EMAIL_ADDRESS_1>."
    )
    print(f"[Simulated LLM Response]\n{llm_response2}\n")

    # --- OUTPUT GUARD ---
    final_output2 = guard2.process_output(llm_response2)
    print(f"\n[Final Output to User]\n{final_output2}\n")

    print("Note: Original PII values restored in output only because they came from user input.")

    # --- AUDIT LOG ---
    print("\n[Audit Log - Demo 2]")
    print(json.dumps(guard2.get_audit_log(), indent=2))


    # ========================================================================
    # DEMO 3: Detecting Hallucinated PII
    # ========================================================================
    print("\n" + "=" * 70)
    print("DEMO 3: Detecting Hallucinated PII")
    print("=" * 70)
    
    guard3 = PresidioGuard(reversible=True, allow_restored_pii=True)
    
    # Reset demonstration: In production, call reset() between different users/sessions
    # to prevent PII leakage. For this demo, we start fresh.
    print("\n[State Management] Starting fresh session with reset guard...")
    
    guard3.process_input(user_input)  # Track known PII

    # LLM hallucinates a new email address
    hallucinated_response = (
        "I've sent the summary to fake.person@newcorp.com and <EMAIL_ADDRESS_1>."
    )
    print(f"\n[LLM Response with Hallucination]\n{hallucinated_response}\n")

    final_output3 = guard3.process_output(hallucinated_response)
    print(f"\n[Final Output]\n{final_output3}\n")
    print("Note: Hallucinated email was caught and redacted!\n")

    # --- AUDIT LOG ---
    print("\n[Audit Log - Demo 3]")
    print(json.dumps(guard3.get_audit_log(), indent=2))

    # ========================================================================
    # DEMO 4: State Management with reset()
    # ========================================================================
    print("\n" + "=" * 70)
    print("DEMO 4: State Management - Why reset() Matters")
    print("=" * 70)
    
    # Simulate a multi-user scenario
    guard_shared = PresidioGuard(reversible=True, allow_restored_pii=True)
    
    # --- USER 1'S SESSION ---
    print("\n--- User 1's Session ---")
    user1_input = "My email is alice@company.com and my ID is EMP-B99999."
    
    sanitized_u1 = guard_shared.process_input(user1_input)
    print(f"\n[Sanitized for LLM]\n{sanitized_u1}\n")
    
    # Simulate LLM response for User 1
    llm_u1 = "I've recorded your email <EMAIL_ADDRESS_1> and ID <EMPLOYEE_ID_1> in the system."
    print(f"[Simulated LLM Response]\n{llm_u1}\n")
    
    output_u1 = guard_shared.process_output(llm_u1)
    print(f"\n[Final Output to User 1]\n{output_u1}\n")
    
    # --- WITHOUT reset() - User 2's session (INSECURE) ---
    print("\n" + "-" * 70)
    print("   WITHOUT reset() - User 2's session (INSECURE)")
    print("-" * 70)
    
    user2_input = "My email is bob@company.com."
    sanitized_u2_bad = guard_shared.process_input(user2_input)
    print(f"\n[Sanitized for LLM]\n{sanitized_u2_bad}\n")
    
    # Simulate LLM response for User 2
    llm_u2_bad = "I've recorded your email <EMAIL_ADDRESS_2>."
    print(f"[Simulated LLM Response]\n{llm_u2_bad}\n")
    
    output_u2_bad = guard_shared.process_output(llm_u2_bad)
    print(f"\n[Final Output to User 2]\n{output_u2_bad}\n")
    
    print(f"   PROBLEM: Mapping contains {len(guard_shared._anonymizer.get_mapping())} items from BOTH users!")
    print("   User 2 could potentially see User 1's PII if placeholders overlap!\n")
    
    # --- WITH reset() - User 2's session (SECURE) ---
    print("\n" + "-" * 70)
    print("   WITH reset() - User 2's session (SECURE)")
    print("-" * 70)
    
    guard_shared.reset()  # Clear state before new user
    print("[State Management] Called reset() - all mappings cleared\n")
    
    sanitized_u2_good = guard_shared.process_input(user2_input)
    print(f"\n[Sanitized for LLM]\n{sanitized_u2_good}\n")
    
    # Simulate LLM response for User 2
    llm_u2_good = "I've recorded your email <EMAIL_ADDRESS_1>."
    print(f"[Simulated LLM Response]\n{llm_u2_good}\n")
    
    output_u2_good = guard_shared.process_output(llm_u2_good)
    print(f"\n[Final Output to User 2]\n{output_u2_good}\n")
    
    print(f"   SECURE: Mapping contains {len(guard_shared._anonymizer.get_mapping())} item(s) from only User 2")
    print("   User 2's data is completely isolated from User 1's session!\n")
    
    print("=" * 70)
    print("Best Practice: Always call reset() between different users/conversations!")
    print("=" * 70)
    
    # --- AUDIT LOG ---
    print("\n[Audit Log - Demo 4 (after reset)]")
    print(json.dumps(guard_shared.get_audit_log(), indent=2))