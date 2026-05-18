import pandas as pd
import xgboost as xgb
import random
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import pickle


print("Loading PhishTank data...")
df_phish = pd.read_csv("dataset_phishtank.csv")
df_phish = df_phish.dropna(subset=["url"])
df_phish["verified"] = df_phish["verified"].astype(str).str.lower().str.strip()
df_phish = df_phish[df_phish["verified"] == "yes"].copy()
df_phish["label"] = 1

phish_keywords = ["login", "verify", "update", "secure", "banking", "account"]

def extract_features(df):
    df["url_length"] = df["url"].apply(len)
    df["num_dots"] = df["url"].apply(lambda x: x.count("."))
    df["is_http"] = df["url"].apply(lambda x: 1 if x.startswith("http://") else 0)
    df["num_hyphens"] = df["url"].apply(lambda x: x.count("-"))
    df["url_depth"] = df["url"].apply(lambda x: x.count("/"))
    df["num_digits"] = df["url"].apply(lambda x: sum(c.isdigit() for c in x))
    df["has_at_symbol"] = df["url"].apply(lambda x: 1 if "@" in x else 0)
    df["contains_kw"] = df["url"].apply(lambda x: 1 if any(kw in x.lower() for kw in phish_keywords) else 0)
    return df

df_phish = extract_features(df_phish)
keep_cols = ["url_length", "num_dots", "is_http", "num_hyphens", "url_depth", "num_digits", "has_at_symbol", "contains_kw", "label"]
df_phish = df_phish[keep_cols]


print("Loading and augmenting Benign data...")
df_benign = pd.read_csv("dataset_benign.csv").dropna(subset=["url"])
df_benign = df_benign.head(len(df_phish)).copy()
df_benign["label"] = 0

random.seed(42)

df_benign["url"] = df_benign["url"].apply(
    lambda x: f"http://www.{x}" if random.random() > 0.85 else f"https://www.{x}"
)

safe_paths = ["/", "/about-us", "/contact/support", "/login.php", "/user/settings", "/secure/auth/verify"]
df_benign["url"] = df_benign["url"].apply(
    lambda x: x + random.choice(safe_paths) if random.random() > 0.15 else x
)

df_benign = extract_features(df_benign)
df_benign = df_benign[keep_cols]


print("Training perfectly balanced XGBoost model...")
df_final = pd.concat([df_phish, df_benign], ignore_index=True)

X = df_final.drop(columns=["label"])
y = df_final["label"]
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

model = xgb.XGBClassifier(use_label_encoder=False, eval_metric='logloss', random_state=42)
model.fit(X_train, y_train)

print(f"Accuracy: {accuracy_score(y_test, model.predict(X_test)) * 100:.2f}%")

with open("phishguard_model.pkl", "wb") as f:
    pickle.dump(model, f)
print("Model saved to 'phishguard_model.pkl'.")