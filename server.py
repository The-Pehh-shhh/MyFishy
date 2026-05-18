import pickle
import pandas as pd
import xgboost as xgb
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="myfishy API", description="API to scan URLs for phishing threats.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

print("Loading model phishguard_model.pkl...")
with open("phishguard_model.pkl", "rb") as f:
    model = pickle.load(f)
print("Model loaded successfully.")

class ScanRequest(BaseModel):
    url: str

@app.post("/scan")
async def scan_url(request: ScanRequest):
    url = request.url

    url_length = len(url)
    num_dots = url.count(".")
    is_http = 1 if url.startswith("http://") else 0
    num_hyphens = url.count("-")
    url_depth = url.count("/")
    num_digits = sum(c.isdigit() for c in url)
    has_at_symbol = 1 if "@" in url else 0

    phish_keywords = ["login", "verify", "update", "secure", "banking", "account"]
    contains_kw = 1 if any(kw in url.lower() for kw in phish_keywords) else 0

    features = {
        "url_length": [url_length],
        "num_dots": [num_dots],
        "is_http": [is_http],
        "num_hyphens": [num_hyphens],
        "url_depth": [url_depth],
        "num_digits": [num_digits],
        "has_at_symbol": [has_at_symbol],
        "contains_kw": [contains_kw]
    }

    df = pd.DataFrame(features)

    prediction = model.predict(df)[0]

    status = "phishing" if int(prediction) == 1 else "safe"

    return {
        "status": status,
        "url": url,
        "features": {
            "url_length": url_length,
            "num_dots": num_dots,
            "is_http": is_http,
            "num_hyphens": num_hyphens,
            "url_depth": url_depth,
            "num_digits": num_digits,
            "has_at_symbol": has_at_symbol,
            "contains_kw": contains_kw
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)