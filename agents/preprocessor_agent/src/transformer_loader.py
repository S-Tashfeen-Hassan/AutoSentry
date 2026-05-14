"""
Load fitted preprocessor (joblib) and mappings.json.
Expose transform_flows(df) that returns DataFrame/array ready for encoder.
"""

import joblib
import json
import os
import pandas as pd
import numpy as np

class TransformerLoader:
    def __init__(self, pipeline_path, mappings_path, preprocessor_config=None):
        if not os.path.exists(pipeline_path):
            raise FileNotFoundError(f"Pipeline not found: {pipeline_path}")
        if not os.path.exists(mappings_path):
            raise FileNotFoundError(f"Mappings not found: {mappings_path}")

        self.pipeline = joblib.load(pipeline_path)
        with open(mappings_path, 'r') as f:
            self.mappings = json.load(f)
        self.config = preprocessor_config or {}

    def map_categorical(self, df):
        # Map proto/service/state using mappings. Unknown -> configured unknown code
        unknown_code = self.config.get('unknown_cat_code', 255)
        for col in ['proto', 'service', 'state']:
            if col not in df.columns:
                df[col] = 'unknown'
            mapping = self.mappings.get(col, {})
            df[col] = df[col].astype(str).str.lower().map(lambda x, m=mapping, uc=unknown_code: m.get(x, m.get(x.upper(), uc)))
        return df

    def transform_flows(self, df):
        """
        df: pandas DataFrame of aggregated flows with exact column names expected by the pipeline.
        Returns the transformed pandas DataFrame (pipeline output, set to pandas).
        """
        # Defensive copy
        dfc = df.copy()

        # Ensure expected columns exist - pipeline will drop/reorder; we attempt to provide all
        # Map categorical values to numeric codes based on mappings
        dfc = self.map_categorical(dfc)

        # The pipeline expects the original columns; do not fit here
        transformed = self.pipeline.transform(dfc)
        # Ensure pandas output (if pipeline .set_output used)
        if isinstance(transformed, np.ndarray):
            # Return numpy array
            return transformed
        return transformed
