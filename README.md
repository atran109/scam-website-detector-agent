# scam-website-detector-agent
Project BloodHound

## Confidence (note for the final README)

Each record has `scam_probability` (0–1); the verdict is `scam` when it is at least 0.45, a deliberate lean toward recall. `confidence` is the probability that the stated verdict is correct (`scam_probability` for scam, `1 - scam_probability` for not_scam). So a site scored 0.45–0.5 is labeled `scam` with confidence below 0.5. That is intended, and it marks the shaky verdicts.
