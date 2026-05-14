"""
Utility to fit the ColumnTransformer on training flows and persist it.
The expected input is a CSV where columns match the 42-field flow schema.
"""

import argparse
import pandas as pd
import numpy as np
import joblib
import json
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler, RobustScaler, MinMaxScaler
from sklearn.compose import ColumnTransformer

def build_and_fit_pipeline(df, mappings, out_path):
    # define columns exactly as in your earlier message
    cat1_cols = [
        'spkts', 'dpkts', 'sbytes', 'dbytes',
        'sload', 'dload', 'rate',
        'sinpkt', 'dinpkt', 'sjit', 'djit',
        'response_body_len', 'sloss', 'dloss', 'ackdat'
    ]
    cat2_cols = ['dur', 'stcpb', 'dtcpb', 'synack', 'tcprtt','smean', 'dmean']
    cat3_cols = [
        'sttl', 'dttl', 'swin', 'dwin',
        'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_state_ttl', 'trans_depth'
    ]
    cat4_cols = ['proto', 'service', 'state', 'ct_srv_src', 'ct_dst_ltm', 'ct_src_dport_ltm',
                 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports', 'is_ftp_login']

    preprocessor = ColumnTransformer(
        transformers=[
            ('log_std', Pipeline([
                ('log', FunctionTransformer(np.log1p, validate=False)),
                ('std', StandardScaler())
            ]), cat1_cols),

            ('robust', RobustScaler(), cat2_cols),

            ('minmax', MinMaxScaler(), cat3_cols),

            ('cat_passthrough', 'passthrough', cat4_cols)
        ],
        remainder='drop',
        verbose_feature_names_out=False
    ).set_output(transform='pandas')

    # Fit
    X = df[cat1_cols + cat2_cols + cat3_cols + cat4_cols]
    fitted = preprocessor.fit(X)
    joblib.dump(fitted, out_path)
    print("Saved pipeline to", out_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--train-csv", required=True, help="Training flows CSV (already aggregated to flows)")
    parser.add_argument("--out", required=True, help="Output joblib path")
    parser.add_argument("--mappings-out", required=False, default=None, help="Optional path to write proto/service/state mappings.json")
    args = parser.parse_args()

    df = pd.read_csv(args.train_csv)
    build_and_fit_pipeline(df, args.mappings_out, args.out)
