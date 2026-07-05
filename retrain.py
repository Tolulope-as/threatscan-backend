import pandas as pd
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import pickle

# Load dataset
df = pd.read_csv("phishing.csv")

# Drop Index column, use all remaining except last (class) as features
X = df.drop(columns=["Index", "class"]).values
y = df["class"].values

print("Number of features:", X.shape[1])

# Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train
model = GradientBoostingClassifier()
model.fit(X_train, y_train)

# Accuracy
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print(f"Model accuracy: {round(accuracy * 100, 2)}%")

# Save
with open("pickle/model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model saved successfully")