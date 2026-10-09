"""Confusion matrices at row level (user-day) and user level (peak daily score).

Usage: python evaluate.py [Capstone_Ready_Data_Final.csv] [threshold=30]
Requires columns: user, risk_score, is_true_insider
A user-day / user is flagged when score >= threshold (Warning tier, default 30).
"""
import sys

import pandas as pd


def metrics(tp, fn, fp, tn):
    rec = tp / (tp + fn) if tp + fn else float("nan")
    prec = tp / (tp + fp) if tp + fp else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else float("nan")
    return {"TP": tp, "FN": fn, "FP": fp, "TN": tn,
            "recall": rec, "precision": prec, "specificity": tn / (tn + fp) if tn + fp else float("nan"),
            "FPR": fp / (fp + tn) if fp + tn else float("nan"), "F1": f1}


def confusion(flag, truth):
    return metrics(int((flag & truth).sum()), int((~flag & truth).sum()),
                   int((flag & ~truth).sum()), int((~flag & ~truth).sum()))


def main(path="Capstone_Ready_Data_Final.csv", threshold=30.0):
    df = pd.read_csv(path)
    truth = df["is_true_insider"].astype(int) == 1
    row = confusion(df["risk_score"] >= threshold, truth)
    u = df.groupby("user").agg(peak=("risk_score", "max"), insider=("is_true_insider", "max"))
    usr = confusion(u["peak"] >= threshold, u["insider"].astype(int) == 1)
    for name, m in (("ROW LEVEL (user-day)", row), ("USER LEVEL (peak score)", usr)):
        print(f"\n{name}")
        for k, v in m.items():
            print(f"  {k:12s} {v:,}" if isinstance(v, int) else f"  {k:12s} {v:.4f}")


if __name__ == "__main__":
    main(*(sys.argv[1:2] or ["Capstone_Ready_Data_Final.csv"]),
         *([float(sys.argv[2])] if len(sys.argv) > 2 else []))
