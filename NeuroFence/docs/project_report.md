# NeuroFence: LLM Weight Poisoning & Backdoor Scanner

**Cyber Security Internship Project Report**  
**Project period:** 05 September 2026 – 05 October 2026  
**Prepared by:** [Intern name]  
**Organization / mentor:** [Add organization and mentor]

## Abstract
NeuroFence is a defensive, static-first scanner that triages machine-learning artifacts before deployment. It calculates SHA-256, identifies formats, inspects selected safe tensor containers, evaluates tensor statistics, flags selected configuration and archive indicators, assigns a transparent heuristic risk score, and persists results through a FastAPI service with SQLite history. Synthetic examples demonstrate checks for non-finite values and extreme magnitudes. NeuroFence never loads pickle-based artifacts. Findings are indicators requiring review; static analysis cannot establish whether an LLM contains a behavioral backdoor.

## 1. Problem statement
Model files can be modified, malformed, mislabeled or acquired from uncertain sources. Intake controls should identify integrity and structure issues without executing untrusted artifacts. Backdoors may remain dormant under ordinary inputs, so numerical checks cannot provide comprehensive detection.

## 2. Objectives
- Record artifact identity using SHA-256, size and detected format.
- Inspect supported tensor metadata and numerical summaries safely.
- Flag non-finite values, unusual magnitudes, selected configuration keys and archive hazards.
- Provide explainable findings and consistent risk bands.
- Expose scanning through a local interface and API with history and reports.
- Demonstrate checks on reproducible synthetic artifacts.

## 3. Scope
Included: `.npz`, `.safetensors` (optional dependency), `.zip`, and conservative flagging for pickle formats such as `.pt`/`.pth`. Statistics include tensor count, parameter count, shape, dtype, mean, standard deviation, extrema and zero fraction. Excluded: arbitrary model execution, pickle deserialization, proof of backdoor absence, universal baselines and active behavioral testing. The interface states behavioral testing was not run.

## 4. Architecture and implementation
The browser sends an artifact to FastAPI. The API streams it to a temporary file, hashes it, enforces a 512 MiB cap, invokes static inspection, persists result data in SQLite and removes the temporary file. The dashboard shows score, risk band, findings and scan history. NumPy reads NPZ with `allow_pickle=False`; safetensors uses its safe API. PDF generation is available through an optional helper.

## 5. Risk model
Severity weights are LOW=5, MEDIUM=18, HIGH=35 and CRITICAL=50; the sum is capped at 100. Unknown or pickle format adds 15. Bands: LOW below 20, MEDIUM from 20, HIGH from 50, CRITICAL from 75. These values prioritize review; they are not probabilities. The transparent, uncalibrated thresholds may produce false positives and false negatives.

## 6. Evaluation
The included deterministic demo generator creates a clean synthetic NPZ and an anomalous NPZ containing NaN and an extreme weight. Expected checks are documented in `evaluation/`. These fixture properties are illustrative, not a representative benchmark. Evaluation covers planted indicators only and does not establish real-world detection rates or backdoor detection capability. No external model is included.

## 7. Results and discussion
The prototype provides a repeatable intake workflow and evidence for triage. Hashes support exact comparison when a trusted digest is available. Tensor statistics identify gross numeric issues; archive and configuration checks add context. A backdoor can have ordinary global statistics and evade static heuristics. Safe behavioral experiments need isolated inference, a trusted baseline and governed trigger candidates; these remain an extension.

## 8. Security and operations
Do not enable arbitrary serialization. Keep the service on localhost unless authentication, authorization, TLS, resource limits, audit logging and retention are added. Parsers retain attack surface. Use disposable isolation for hostile artifacts. A LOW score is not approval; a HIGH score is not proof of maliciousness.

## 9. Future work
Add signed architecture-matched baselines, calibrated layer checks, sandboxed inference with reviewed behavioral tests, authentication, retention and audit controls, and evaluation on a larger labeled collection.

## 10. Conclusion
NeuroFence demonstrates safe artifact triage with explainable signals, a usable interface and persistent reports. It is a foundation for supply-chain review and clearly separates static indicators from behavioral backdoor assessment.

## References
1. Safetensors documentation, https://huggingface.co/docs/safetensors/ (accessed 2026-09-29).
2. NumPy `load` documentation, https://numpy.org/doc/stable/reference/generated/numpy.load.html (accessed 2026-09-29).
3. FastAPI documentation, https://fastapi.tiangolo.com/ (accessed 2026-09-29).
4. Python `pickle` documentation, https://docs.python.org/3/library/pickle.html (accessed 2026-09-29).
