#!/usr/bin/env python3
"""
Daily Bahamas DL risk-limit script – transcribed from IMG_8391-8394.JPG
"""

import datetime as dt
import os
import requests
import numpy as np
import pandas as pd
from pandas.tseries.offsets import BDay
from dateutil.relativedelta import relativedelta

from rfm.atom import (
    getDSRVAR_ByDateList,
    getATOMTenorPV01Details_ByDateList,
    getDSRVAR_ByDateRange,
)
from rfm.tlam import lamp_upload
from rfm.tools import write_to_db, delete_from_db

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
Bahamas_Node = "84273_DISCRETIONARY LENDING BAHAMAS"

BMA_USER = os.environ.get("BMA_USER")
BMA_PASS = os.environ.get("BMA_PASS")

LAMP_UPLOAD = True
env = "PROD"


# ----------------------------------------------------------------------
if __name__ == "__main__":
    # ------------------------------------------------------------------
    # 1. Query ATOM for yesterday’s data
    # ------------------------------------------------------------------
    date = dt.date.today() - BDay(1)
    print(date)
    print("querying ATOM")

    df_tenorPV01 = getATOMTenorPV01Details_ByDateList(
        f"{date:%Y-%m-%d}", Bahamas_Node, ["INCLUDE_ALL"]
    )

    df = df_tenorPV01[df_tenorPV01["pnl.pn1"] != 0]
    df = df[df["pnl.pn1"].notnull()]

    df.rename(
        columns={
            "instrument.currency": "ccy",
            "pnl.pn1": "pv01",
            "instrument.instrumentName": "instrument",
            "positionName": "id",
            "instrument.daysToMaturity": "TTM",
        },
        inplace=True,
    )

    # ------------------------------------------------------------------
    # 2. Enrich / tidy columns
    # ------------------------------------------------------------------
    df["business_date"] = f"{date:%Y-%m-%d}"
    df["maturity_date"] = (
        pd.to_datetime(df["business_date"])
        + pd.to_timedelta(df["TTM"].astype(int), unit="D")
    )
    df["business_date"] = df["business_date"].astype(str)
    df["maturity_date"] = df["maturity_date"].astype(str)

    df["bkt"] = df["id"].apply(lambda x: x.split("_")[-1])
    df["book"] = df["book.bookName"].apply(lambda x: x.split(".")[-1])
    df["sys_source"] = df["book.bookName"].apply(lambda x: x.split("_")[0])
    df["trade_id"] = df["id"].apply(
        lambda x: x.split("_")[1] if len(x.split("_")) == 2 else x.split("_")[0]
    )
    df["instr_type"] = df["instrument"].apply(lambda x: x.split(" ")[0])
    df["instr_details"] = df["instrument"].apply(
        lambda x: x.split(" ")[1] if len(x.split(" ")) > 1 else ""
    )

    df["instr_type"] = np.where(
        df["instrument"].str.contains("FX FORWARD"),
        "FX",
        np.where(
            df["instrument"].str.contains("FLOATOX"),
            "XCCY Swap",
            np.where(
                df["instrument"].str.contains("Mux_RN_Cash_Transfer"),
                "Cash Transfer",
                np.where(df["instrument"].str.contains("XCF"), "FX Forward", df["instr_type"]),
            ),
        ),
    )

    # ------------------------------------------------------------------
    # 3. Aggregate to one row per trade and write to DB
    # ------------------------------------------------------------------
    df_agg = df.copy()

    cols = [
        "business_date",
        "inst_type",
        "trade_id",
        "maturity_date",
        "book",
        "sys_source",
        "ccy",
        "bkt",
        "pv01",
    ]
    df = df[cols]
    df = (
        df.groupby(
            [
                "business_date",
                "inst_type",
                "trade_id",
                "maturity_date",
                "book",
                "sys_source",
                "ccy",
                "bkt",
            ],
            as_index=False,
        )
        .sum()
    )
    print(df)

    query = """
        INSERT INTO bahamas_atom_pv01
            (business_date, inst_type, trade_id, maturity_date,
             book, sys_source, ccy, bkt, pv01)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    # Delete existing rows for this date
    criteria = f""" business_date = '{date:%Y-%m-%d}' """
    delete_from_db(table_name="bahamas_atom_pv01", condition=criteria, env="QA", fast=False)

    # Keep only the most recent month of history
    past31_date = dt.date.today() - BDay(31)
    criteria = f""" business_date < '{past31_date:%Y-%m-%d}' """
    delete_from_db(table_name="bahamas_atom_pv01", condition=criteria, env="QA", fast=False)
    print("Deleted:", criteria)

    write_to_db(query=query, values=df.values, env="QA", fast=True)

    # ------------------------------------------------------------------
    # 4. Limit-calculation section
    # ------------------------------------------------------------------
    total_pv01 = df["pv01"].sum()

    swap_df = df[df["inst_type"] == "XCCY Swap"]
    cad_spread = swap_df["pv01"].sum()
    basis_spread_pv01 = cad_spread

    df_oq = df.copy()
    max_tenor = float(df_oq["TTM"].astype(int).max()) / 365

    base_url = "https://ends.cs.rbc.com/v1/marketdata/RATS-TOR/"
    url = (
        f"{base_url}curve_name=FX_USDCAD&business_date={date:%Y-%m-%d}"
        f"&from=1960-01-01"
    )

    resp = requests.get(url, verify=False, auth=(BMA_USER, BMA_PASS))
    resp = resp.json()
    resp = resp["marketdata"]
    data = pd.DataFrame(resp)

    FXrate = data["value"].iloc[0]
    print("USDCAD FX:", FXrate)

    fund_notional_CAD = -3_500_000_000
    fund_notional_USD = float((1 / FXrate) * fund_notional_CAD)

    net_eq_delta = 0
    single_name_delta = 0

    start = date - BDay(0)
    dates = pd.date_range(start=start, end=date, freq="B")
    datelist = list(map(lambda x: x.date().strftime("%Y-%m-%d"), dates))

    dl_VaR_df = getDSRVAR_ByDateRange(
        datelist[0], datelist[-1], [Bahamas_Node], ["MTM Limits"], 5314
    )
    dl_VaR = dl_VaR_df["value"].values[0]
    print("DL Bahamas - VaR:", dl_VaR)

    if LAMP_UPLOAD:
        lamp_upload(env, date, 12361, float(total_pv01))
        lamp_upload(env, date, 12362, float(basis_spread_pv01))
        lamp_upload(env, date, 12363, float(fund_notional_USD))
        lamp_upload(env, date, 12364, float(max_tenor))
        lamp_upload(env, date, 12365, float(net_eq_delta))
        lamp_upload(env, date, 12366, float(single_name_delta))
        lamp_upload(env, date, 12365, float(dl_VaR))   # ← duplicated ID in original

    # ------------------------------------------------------------------
    # 5. Collateral (T-1) calculation
    # ------------------------------------------------------------------
    path = (
        r"\\castvsfg6.fg.rbc.com\UR2$\PROD\data\output\SFRS_PDR"
        fr"\{date:%Y%m%d}\SECFINPosDetails_{date:%Y%m%d}.csv"
    )

    df_secfin = pd.read_csv(path)

    baha_book = "RBCB:FF"
    df_baha = df_secfin[df_secfin["book"] == baha_book]

    internal_flag = ["I"]
    internal_filter = df_baha["Internal/CCP Flag"].isin(internal_flag)

    # drop internal trades
    df_baha = df_baha[~internal_filter]
    print(df_baha)

    collateral = df_baha["collateral"].sum()
    print("T-1 Collateral:", collateral)

    if LAMP_UPLOAD:
        lamp_upload(env, date, 12367, float(collateral))
