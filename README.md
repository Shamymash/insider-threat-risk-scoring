# Insider-Threat Risk Scoring: Code for a Transparent, Ethically-Bounded Framework

Code accompanying the paper *A Transparent, Ethically-Bounded Framework for Insider-Threat Risk Scoring in Financial Services* (Mashayekhi, Fox, Pradhan, Lyons & Saheb, 2026). Preprint: https://doi.org/10.2139/ssrn.7500999

The framework is a deterministic, white-box score: every value can be recomputed by hand from the daily counts.

## The formula

```
RiskScore = (AH x 20) + (USB x 30) + (E x 2) + (F x 0.5) + ((N + (50 - C)) x 0.2)    capped at 100
```

| Term | Meaning |
|---|---|
| AH | after-hours logons (20:00-05:59) that day |
| USB | removable-media connect events that day |
| E | emails sent that day |
| F | file-access events that day |
| N, C | Neuroticism and Conscientiousness (Five-Factor scores; missing -> neutral 30) |

**Ethical bound.** The psychometric term cannot exceed 20 points, below the 30-point Warning threshold, so personality data alone can never trigger a flag.

Tiers: Warning >= 30, Critical >= 70.

## Files

| File | Purpose |
|---|---|
| `etl_processor.py` | Builds the daily behavioural matrix (one row per user-day) from the six raw tables and computes the score |
| `evaluate.py` | Row-level and user-level confusion matrices and metrics at a given threshold |
| `dashboard_app.py` | Streamlit analyst dashboard (risk timeline, per-vector metrics, drill-down) |
| `results/verified_results.md` | Confusion matrices reported in the paper |

## Reproducing

1. Obtain CERT Insider Threat Dataset r4.2 from the Software Engineering Institute, Carnegie Mellon University. The raw data is not redistributed here.
2. Place `logon.csv`, `device.csv`, `email.csv`, `file.csv`, `psychometric.csv` (with a `user_id` column) and `insiders.csv` (ground-truth list of the 70 malicious users, `user` column) in one folder with the scripts.
3. Run:
   ```
   pip install pandas streamlit plotly
   python etl_processor.py        # writes Capstone_Ready_Data_Final.csv
   python evaluate.py Capstone_Ready_Data_Final.csv 30
   streamlit run dashboard_app.py
   ```

## Reported results (flag if score >= 30)

| Level | TP | FN | FP | TN | Recall | Precision |
|---|---|---|---|---|---|---|
| User (peak score) | 70 | 0 | 526 | 404 | 100% | 11.74% |
| Row (user-day) | 11,657 | 3,793 | 155,329 | 159,673 | 75.45% | 6.98% |

## Limitations

CERT r4.2 is synthetic; results show internal validity only. Weights and thresholds are static. The dashboard highlights scores above 30 (strict), while the paper's evaluation flags scores of 30 or more. See the paper's Limitations section.

## License

MIT (see `LICENSE`). Cite via `CITATION.cff`.
