import numpy as np
import pandas as pd

# List of CSE-CIC-IDS2018 features that have zero variance across clean network flows
CONSTANT_ZERO_FEATURES = [
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "CWE Flag Count",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate"
]

def analyze_features_on_training_data(
    train_df: pd.DataFrame,
    feature_cols: list,
    target_col: str = "final_label"
) -> dict:
    """Analyze feature statistics strictly on training data without cross-split leakage."""
    results = {
        "total_features": len(feature_cols),
        "constant_features": [],
        "quasi_constant_features": [],
        "high_correlation_pairs": [],
        "feature_variance_ranks": []
    }
    
    # 1. Variance & Constant Analysis
    variances = {}
    for col in feature_cols:
        col_series = train_df[col].dropna()
        if len(col_series) == 0:
            continue
        var = float(col_series.var())
        n_unique = col_series.nunique()
        
        if n_unique <= 1 or var == 0.0 or np.isnan(var):
            results["constant_features"].append(col)
        else:
            top_freq = col_series.value_counts(normalize=True).iloc[0]
            if top_freq >= 0.999:
                results["quasi_constant_features"].append({"feature": col, "dominant_pct": float(top_freq)})
        variances[col] = 0.0 if np.isnan(var) else var

    # Sort features by variance
    sorted_vars = sorted(variances.items(), key=lambda x: x[1], reverse=True)
    results["feature_variance_ranks"] = [{"feature": k, "variance": v} for k, v in sorted_vars[:20]]

    # 2. Correlation Analysis (Sample-based if large for efficiency)
    sample_size = min(len(train_df), 10000)
    sample_df = train_df[feature_cols].sample(n=sample_size, random_state=42) if len(train_df) > sample_size else train_df[feature_cols]
    
    # Exclude constant features from correlation
    active_cols = [c for c in feature_cols if c not in results["constant_features"]]
    if len(active_cols) > 1:
        corr_matrix = sample_df[active_cols].corr().abs()
        upper_tri = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
        for col_a in upper_tri.columns:
            high_corr = upper_tri[col_a][upper_tri[col_a] > 0.98]
            for col_b, val in high_corr.items():
                results["high_correlation_pairs"].append({
                    "feature_1": col_a,
                    "feature_2": col_b,
                    "correlation": float(val)
                })

    return results

def compute_engineered_flow_features(df: pd.DataFrame) -> pd.DataFrame:
    """Compute leakage-free, row-wise network flow features.
    
    All computations are purely vectorized row-by-row mathematical functions,
    ensuring zero cross-sample leakage between records.
    """
    df_out = df.copy(deep=False)
    
    # 1. Packet asymmetry and volume ratios
    if "Total Fwd Packets" in df.columns and "Total Backward Packets" in df.columns:
        fwd_pkts = df["Total Fwd Packets"].astype(np.float32)
        bwd_pkts = df["Total Backward Packets"].astype(np.float32)
        df_out["fwd_bwd_pkt_ratio"] = fwd_pkts / (bwd_pkts + 1.0)
        df_out["total_flow_packets"] = fwd_pkts + bwd_pkts

    if "Fwd Packets Length Total" in df.columns and "Bwd Packets Length Total" in df.columns:
        fwd_bytes = df["Fwd Packets Length Total"].astype(np.float32)
        bwd_bytes = df["Bwd Packets Length Total"].astype(np.float32)
        df_out["fwd_bwd_byte_ratio"] = fwd_bytes / (bwd_bytes + 1.0)
        df_out["total_flow_bytes"] = fwd_bytes + bwd_bytes

    # 2. Average bytes per packet
    if "Fwd Packets Length Total" in df.columns and "Total Fwd Packets" in df.columns:
        df_out["bytes_per_fwd_pkt"] = df["Fwd Packets Length Total"].astype(np.float32) / (df["Total Fwd Packets"].astype(np.float32) + 1.0)

    if "Bwd Packets Length Total" in df.columns and "Total Backward Packets" in df.columns:
        df_out["bytes_per_bwd_pkt"] = df["Bwd Packets Length Total"].astype(np.float32) / (df["Total Backward Packets"].astype(np.float32) + 1.0)

    # 3. Header to payload ratios (reveals scanning and packet crafting attacks)
    if "Fwd Header Length" in df.columns and "Fwd Packets Length Total" in df.columns:
        df_out["hdr_payload_ratio_fwd"] = df["Fwd Header Length"].astype(np.float32) / (df["Fwd Packets Length Total"].astype(np.float32) + 1.0)

    # 4. Inter-arrival time spread
    if "Flow IAT Max" in df.columns and "Flow IAT Min" in df.columns:
        df_out["flow_iat_spread"] = df["Flow IAT Max"].astype(np.float32) - df["Flow IAT Min"].astype(np.float32)

    return df_out

def apply_feature_representation(
    df: pd.DataFrame,
    representation: str = "all_77"
) -> pd.DataFrame:
    """Transform DataFrame features according to the chosen representation."""
    if representation == "all_77":
        return df
        
    elif representation == "curated_subset":
        # Drop constant zero features that provide no discriminatory signal
        cols_to_drop = [c for c in CONSTANT_ZERO_FEATURES if c in df.columns]
        return df.drop(columns=cols_to_drop, errors="ignore")
        
    elif representation == "engineered":
        # Add leakage-safe domain ratios and drop zero variance columns
        df_eng = compute_engineered_flow_features(df)
        cols_to_drop = [c for c in CONSTANT_ZERO_FEATURES if c in df_eng.columns]
        return df_eng.drop(columns=cols_to_drop, errors="ignore")
        
    else:
        raise ValueError(f"Unknown feature representation: {representation}")
