"""ETL and deterministic risk scoring for the CERT Insider Threat Dataset r4.2.

Reads six raw tables from the working directory, builds one row per user-day,
and applies the white-box risk formula described in the paper:

    RiskScore = (AH*20) + (USB*30) + (E*2) + (F*0.5) + ((N + (50 - C)) * 0.2), capped at 100

Output: Capstone_Ready_Data_Final.csv
"""
import os

import pandas as pd

FILES = {
    "logon": "logon.csv",
    "device": "device.csv",
    "email": "email.csv",
    "file": "file.csv",
    "psychometric": "psychometric.csv",
    "insiders": "insiders.csv",
}


def clean_user(series):
    """Strip whitespace, drop any DOMAIN/ prefix, lowercase."""
    return series.astype(str).str.strip().apply(lambda x: x.split("/")[-1].lower())


def daily_counts(path, name, activity_filter=None):
    if not os.path.exists(path):
        return pd.DataFrame(columns=["user", "day", name])
    df = pd.read_csv(path)
    df["user"] = clean_user(df["user"])
    df["day"] = pd.to_datetime(df["date"], errors="coerce").dt.date
    if activity_filter:
        df = df[df["activity"] == activity_filter]
    return df.groupby(["user", "day"]).size().reset_index(name=name)


def process_data():
    print("Starting ETL pipeline...")

    # 1. Logon: after-hours = 20:00-05:59
    if os.path.exists(FILES["logon"]):
        df_logon = pd.read_csv(FILES["logon"])
        df_logon["user"] = clean_user(df_logon["user"])
        df_logon["date"] = pd.to_datetime(df_logon["date"], errors="coerce")
        df_logon["is_after_hours"] = df_logon["date"].dt.hour.apply(
            lambda x: 1 if (pd.notna(x) and (x >= 20 or x < 6)) else 0
        )
        daily_logon = (
            df_logon.groupby(["user", df_logon["date"].dt.date])
            .agg(after_hours_logins=("is_after_hours", "sum"))
            .reset_index()
            .rename(columns={"date": "day"})
        )
    else:
        daily_logon = pd.DataFrame(columns=["user", "day", "after_hours_logins"])

    # 2-4. Device (USB connects), email, file
    daily_device = daily_counts(FILES["device"], "usb_connects", "Connect")
    daily_email = daily_counts(FILES["email"], "emails_sent")
    daily_file = daily_counts(FILES["file"], "files_accessed")

    # 5. Merge
    master_df = pd.merge(daily_logon, daily_device, on=["user", "day"], how="outer")
    master_df = pd.merge(master_df, daily_email, on=["user", "day"], how="outer")
    master_df = pd.merge(master_df, daily_file, on=["user", "day"], how="outer")
    master_df.fillna(0, inplace=True)

    # 6. Psychometrics (missing -> neutral baseline C = N = 30)
    if os.path.exists(FILES["psychometric"]):
        df_psych = pd.read_csv(FILES["psychometric"])
        df_psych["user"] = df_psych["user_id"].astype(str).str.lower().str.strip()
        master_df = pd.merge(master_df, df_psych[["user", "C", "N"]], on="user", how="left")
    else:
        master_df["C"] = float("nan")
        master_df["N"] = float("nan")
    master_df["C"] = master_df["C"].fillna(30.0)
    master_df["N"] = master_df["N"].fillna(30.0)

    # 7. Ground truth
    if os.path.exists(FILES["insiders"]):
        df_ins = pd.read_csv(FILES["insiders"])
        df_ins["user"] = df_ins["user"].astype(str).str.lower().str.strip()
        df_ins["is_true_insider"] = 1
        master_df = pd.merge(
            master_df, df_ins[["user", "is_true_insider"]].drop_duplicates("user"),
            on="user", how="left",
        ).fillna({"is_true_insider": 0})
    else:
        master_df["is_true_insider"] = 0

    # 8. Risk score; the 0.2 multiplier caps the psychometric term at 20 points
    master_df["risk_score"] = (
        master_df["after_hours_logins"] * 20
        + master_df["usb_connects"] * 30
        + master_df["emails_sent"] * 2
        + master_df["files_accessed"] * 0.5
        + (master_df["N"] + (50 - master_df["C"])) * 0.2
    )
    master_df["risk_score"] = master_df["risk_score"].clip(upper=100)

    master_df.to_csv("Capstone_Ready_Data_Final.csv", index=False)
    print("Pipeline complete: 'Capstone_Ready_Data_Final.csv' created.")


if __name__ == "__main__":
    process_data()
