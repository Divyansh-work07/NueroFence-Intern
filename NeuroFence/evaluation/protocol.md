# Evaluation protocol

Generate fixtures with `python evaluation/make_demo.py` from the project root. The script uses deterministic synthetic arrays and downloads no models.

- `clean_demo.npz`: two small finite arrays; expected LOW risk.
- `anomalous_demo.npz`: one NaN and one magnitude-250 weight; expected `NONFINITE_WEIGHT` and `EXTREME_MAGNITUDE`, HIGH risk.
- `unsafe_format_demo.pt`: a text placeholder; expected `UNSAFE_SERIALIZATION` from extension only, and is never deserialized.

These are expected fixture properties, not independently measured benchmark claims. They do not validate real-world backdoor detection.
