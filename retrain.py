import pandas as pd
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
import pickle

df = pd.read_csv("phishing.csv")

X = df.drop(columns=["Index", "class"]).values
y = df["class"].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = GradientBoostingClassifier()
model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("=" * 50)
print("MODEL EVALUATION METRICS")
print("=" * 50)
print(f"Accuracy:  {round(accuracy_score(y_test, predictions) * 100, 2)}%")
print(f"Precision: {round(precision_score(y_test, predictions) * 100, 2)}%")
print(f"Recall:    {round(recall_score(y_test, predictions) * 100, 2)}%")
print(f"F1 Score:  {round(f1_score(y_test, predictions) * 100, 2)}%")
print()
print("Confusion Matrix:")
print(confusion_matrix(y_test, predictions))
print()
print("Full Classification Report:")
print(classification_report(y_test, predictions))

with open("pickle/model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model saved successfully")