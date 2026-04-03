import pandas as pd
import numpy as np
import pickle
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.features import extract_features, get_feature_names
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

print("=" * 60)
print("PHISHING DETECTOR - TRAINING THE ML MODEL")
print("=" * 60)

print("\n[1/4] Creating training data...")

safe_urls = [
    "https://www.google.com/search?q=weather",
    "https://github.com/trending",
    "https://stackoverflow.com/questions",
    "https://en.wikipedia.org/wiki/Python",
    "https://www.youtube.com/watch?v=abc123",
    "https://www.amazon.com/products",
    "https://www.microsoft.com/en-us",
    "https://docs.python.org/3/tutorial",
    "https://www.linkedin.com/in/profile",
    "https://twitter.com/home",
    "https://www.reddit.com/r/cybersecurity",
    "https://news.ycombinator.com",
    "https://www.bbc.com/news",
    "https://mail.google.com/mail",
    "https://drive.google.com/drive/folders",
    "https://www.coursera.org/learn/python",
    "https://www.npmjs.com/package/react",
    "https://pypi.org/project/scikit-learn",
    "https://developer.mozilla.org/en-US/docs",
    "https://www.w3schools.com/python",
] * 50

phishing_urls = [
    "http://paypal-secure-login.verify-account.com/update?token=abc123",
    "http://192.168.1.100/login/secure/paypal/verify",
    "http://amazon-prize-winner.free-gift.tk/claim?id=99999",
    "http://secure-banking.login-update.support/signin",
    "http://faceb00k-account-suspended.tk/login?next=home",
    "http://apple.id-verification-required.com/verify",
    "http://netflix-billing.update-payment.net/secure",
    "http://bit.ly/3xKLmno",
    "http://tinyurl.com/secure-banking-login",
    "http://www.paypa1.com.evil-site.ru/signin",
    "http://bankofamerica.secure-update.phishing.com/login",
    "http://google.account-security-alert.tk",
    "http://microsoft.com.password-reset.support/verify",
    "http://urgent-account-suspended.login-here.com:8080",
    "http://free-iphone14-winner.claim-prize.ga/form",
    "http://steam-trading.scam-site.pw/login?ref=discord",
    "http://fake-amazon.com.purchase-refund.xyz/signin",
    "http://dropbox.file-share.phishing.net/download",
    "http://instagram-verify@evil-login.com/confirm",
    "http://whatsapp-update.security-patch.tk/install",
] * 50

all_urls = safe_urls + phishing_urls
labels = [0] * len(safe_urls) + [1] * len(phishing_urls)

print(f"   Total URLs: {len(all_urls)}")
print(f"   Safe URLs: {len(safe_urls)}")
print(f"   Phishing URLs: {len(phishing_urls)}")

print("\n[2/4] Extracting features from each URL...")

X = []
for i, url in enumerate(all_urls):
    features = extract_features(url)
    X.append(features)

X = np.array(X)
y = np.array(labels)

print(f"   Done! Shape: {X.shape}")

print("\n[3/4] Training Random Forest model...")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)
print("   Training complete!")

print("\n[4/4] Testing model accuracy...")

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\n   Accuracy: {accuracy * 100:.2f}%")
print("\n" + classification_report(y_test, y_pred,
      target_names=['Safe', 'Phishing']))

os.makedirs("ml", exist_ok=True)
with open("ml/phishing_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("=" * 60)
print("Model saved to: ml/phishing_model.pkl")
print("You can now run the web app!")
print("=" * 60)