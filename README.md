# PhishGuard

PhishGuard is a Machine Learning powered real-time URL scanner that detects phishing websites. This project consists of an XGBoost machine learning model, a FastAPI backend server, and a Manifest V3 Chrome Extension.

## Components

1. **Machine Learning Model (`phishguard_model.pkl`)**: An XGBoost classifier trained to detect malicious URLs based on various extracted features.
2. **FastAPI Backend (`server.py`)**: A lightweight Python backend that loads the ML model and provides an API endpoint for predicting whether a given URL is a phishing link.
3. **Chrome Extension (`extension/`)**: A Manifest V3 Chrome extension that captures the URL of your active tab and queries the backend in real-time, displaying a modern glassmorphism UI with the results.

## Setup Instructions

### 1. Start the FastAPI Backend

You need Python 3 installed.

First, install the required dependencies:
```bash
pip install fastapi uvicorn pandas xgboost pydantic
```

Next, start the server locally:
```bash
uvicorn server:app --reload
```
The server will start running at `http://127.0.0.1:8000`. Leave this terminal window open.

### 2. Load the Chrome Extension

1. Open Google Chrome.
2. Navigate to `chrome://extensions/` in your URL bar.
3. In the top right corner, toggle **Developer mode** to ON.
4. Click the **Load unpacked** button in the top left.
5. Select the `extension` folder located inside this project directory.
6. The PhishGuard extension should now appear in your list of extensions.

### 3. Usage

1. Navigate to any website in Chrome.
2. Click the puzzle icon in the top right of Chrome and pin the PhishGuard extension to your toolbar for easy access.
3. Click the PhishGuard extension icon. 
4. The extension will grab the current URL, send it to your local FastAPI server, and immediately display whether the site is **Safe** or a **Phishing** threat!

*Note: The backend server must be running for the extension to work.*
