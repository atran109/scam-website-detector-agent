# scam-website-detector-agent
Project BloodHound

## Confidence (note for the final README)

Each record has `scam_probability` (0–1); the verdict is `scam` when it is at least 0.45, a deliberate lean toward recall. `confidence` is the probability that the stated verdict is correct (`scam_probability` for scam, `1 - scam_probability` for not_scam). So a site scored 0.45–0.5 is labeled `scam` with confidence below 0.5. That is intended, and it marks the shaky verdicts.

## Limitations (notes for the final README)

- Evidence was collected from a residential US IP. Some sites that look dead or time out may be geo-blocking that country or IP range rather than being down; residential/regional proxies are future work (DESIGN A13).
- Dead sites are judged on recovered evidence first (Wayback snapshot), then on domain/sibling/warning-page signals; `evidence_source` on each record says which (DESIGN §5.2a).

## Reviewing a run

`make review RUN=<id>` builds `runs/<id>/review/index.html` (one card per site, borderline verdicts first) and `labels_template.csv` from saved evidence only. It needs no containers and visits nothing. Open the HTML from that folder; it is a static page with no JavaScript.
