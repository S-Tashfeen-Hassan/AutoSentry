"""
aggregate_events_to_flow(events, flow_key, agg_dict) -> DataFrame
"""

import pandas as pd

def aggregate_events_to_flow(events, flow_key, agg_dict):
    """
    events: list of normalized dicts
    flow_key: list of columns used as grouping keys
    agg_dict: dict mapping field->agg
    returns: pandas.DataFrame with aggregated flows
    """
    if not events:
        return pd.DataFrame(columns=flow_key + list(agg_dict.keys()))
    df = pd.DataFrame(events)

    # Ensure grouping keys exist
    for k in flow_key:
        if k not in df.columns:
            df[k] = 'unknown' if k in ['proto','service','state'] else 0

    # Convert possible mixed types for grouping
    grouped = df.groupby(flow_key).agg(agg_dict).reset_index()

    # Ensure column order consistent: flow_key then sorted remainder to stable order
    cols = flow_key + [c for c in grouped.columns if c not in flow_key]
    grouped = grouped[cols]
    return grouped
