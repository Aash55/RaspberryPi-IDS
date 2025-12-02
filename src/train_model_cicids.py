import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib


def to_binary_label(x: str) -> int:
    # normalize string just in case
    x = str(x).strip().lower()
    return 0 if x == "normal traffic" else 1


if __name__ == "__main__":
    # 1) LOAD DATA
    print("🔵 Loading dataset...")
    df = pd.read_csv("dataset/cicids2017_cleaned.csv")
    print("Dataset shape:", df.shape)

    print("\n🔵 Sample rows:")
    print(df.head())

    print("\n🔵 Columns:")
    print(df.columns)

    # 2) CLEAN DATA (safety)
    print("\n🔵 Cleaning dataset (replace inf/NaN)...")
    df.replace([np.inf, -np.inf], 0, inplace=True)
    df.fillna(0, inplace=True)

    # 3) BINARY LABEL: 0 = normal, 1 = attack
    # Your label column is "Attack Type" with values like "Normal Traffic", "DDoS", etc.
    print("\n🔵 Original Attack Type value counts:")
    print(df["Attack Type"].value_counts())

    df["binary_label"] = df["Attack Type"].apply(to_binary_label)

    print("\n🔵 Binary label counts (0=normal, 1=attack):")
    print(df["binary_label"].value_counts())

    # 4) OPTIONAL: DOWNSAMPLE (so training is fast and fits in RAM)
    # take at most 150k normals + 150k attacks
    MAX_PER_CLASS = 150_000

    normal_df = df[df["binary_label"] == 0]
    attack_df = df[df["binary_label"] == 1]

    normal_sample = normal_df.sample(
        n=min(len(normal_df), MAX_PER_CLASS),
        random_state=42
    )
    attack_sample = attack_df.sample(
        n=min(len(attack_df), MAX_PER_CLASS),
        random_state=42
    )

    df_small = pd.concat([normal_sample, attack_sample]).sample(frac=1.0, random_state=42)
    print("\n🔵 After sampling:")
    print("Shape:", df_small.shape)
    print(df_small["binary_label"].value_counts())

    # 5) CHOOSE FEATURES (must exist in your dataset and be computable on Pi)
    feature_cols = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Length of Fwd Packets",
        "Packet Length Mean",
        "Flow Bytes/s",
        "Flow Packets/s",
    ]

    missing = [c for c in feature_cols if c not in df_small.columns]
    if missing:
        raise ValueError(f"Missing expected feature columns: {missing}")

    X = df_small[feature_cols]
    y = df_small["binary_label"]

    print("\n🔵 Feature matrix shape:", X.shape)
    print("Features used:", feature_cols)

    # 6) TRAIN/TEST SPLIT
    print("\n🔵 Splitting train/test...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )
    print("Train size:", X_train.shape, "Test size:", X_test.shape)

    # 7) TRAIN RandomForest MODEL
    print("\n🔵 Training RandomForest model (this may take a few minutes)...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        n_jobs=-1,
        class_weight="balanced",
        random_state=42,
    )
    model.fit(X_train, y_train)

    # 8) EVALUATE
    print("\n🔵 Evaluating model...")
    y_pred = model.predict(X_test)

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, digits=4))

    # 9) FEATURE IMPORTANCE
    print("\n🔵 Feature Importances:")
    importances = model.feature_importances_
    for col, imp in sorted(zip(feature_cols, importances), key=lambda x: x[1], reverse=True):
        print(f"{col:25s} {imp:.4f}")

    # 10) SAVE MODEL
    OUT_MODEL = "ids_rf.joblib"
    joblib.dump(model, OUT_MODEL)
    print(f"\n✅ Model saved to {OUT_MODEL}")
