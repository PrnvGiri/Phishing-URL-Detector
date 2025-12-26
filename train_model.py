import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization
from feature_extractor import FeatureExtractor
import os

# Limit GPU memory growth if applicable
gpus = tf.config.experimental.list_physical_devices('GPU')
if gpus:
    try:
        for gpu in gpus:
            tf.config.experimental.set_memory_growth(gpu, True)
    except RuntimeError as e:
        print(e)

def compute_new_features(df, extractor):
    print("Computing new features (this might take a moment)...")
    # We only compute features that are NOT in the CSV but are in our extractor
    # Actually, for consistency, let's re-compute EVERYTHING or just the missing ones.
    # To be safe and ensure the 'extraction logic' is identical to inference, 
    # we should ideally re-compute. However, 235k rows is a lot.
    # Best compromise: Use existing columns where possible, compute new ones.
    
    # Existing columns in dataset that match our FeatureExtractor names directly (or close enough)
    # The dataset has 'URLLength', 'DomainLength', etc.
    # Let's trust the dataset for basic counts to save time, but compute the new advanced ones.
    
    urls = df['URL'].astype(str).tolist()
    
    suspicious_counts = []
    entropies = []
    is_shortened = []
    has_at = []
    
    for url in urls:
        feats = extractor.extract_features(url)
        suspicious_counts.append(feats['SuspiciousKeywords'])
        entropies.append(feats['Entropy'])
        is_shortened.append(feats['IsShortened'])
        has_at.append(feats['HasAtSymbol'])
        
    df['SuspiciousKeywords'] = suspicious_counts
    df['Entropy'] = entropies
    df['IsShortened'] = is_shortened
    df['HasAtSymbol'] = has_at
    
    return df

def train():
    dataset_path = r'c:\Aryan\PhishingURLDetector\dataset\PhiUSIIL_Phishing_URL_Dataset.csv'
    print(f"Loading dataset from {dataset_path}...")
    try:
        df = pd.read_csv(dataset_path)
    except Exception as e:
        print(f"Error loading dataset: {e}")
        return

    extractor = FeatureExtractor()
    desired_features = extractor.get_feature_names()
    
    # Compute the new features that aren't in the CSV
    df = compute_new_features(df, extractor)
    
    # Check for missing columns again (some basic ones might need mapping if naming differs)
    # Mapping based on typical dataset names vs our names:
    # URLCharProb -> Maybe not calculating this complex one
    # Let's check which desired features are missing
    missing = [col for col in desired_features if col not in df.columns]
    if missing:
        print(f"Warning: The following features are missing from dataset and weren't computed: {missing}")
        # In a real scenario, we'd compute them. For now, let's assume standard names match or we coded them.
        # If URLLength etc are missing, we'd have an issue.
        # Force re-compute of ALL features to be 100% safe if we have time? 
        # Let's try to map or fill.
        pass

    # Select features
    # Ensure all columns exist
    for col in desired_features:
        if col not in df.columns:
            # Fallback: compute it row by row if we missed it
            print(f"Computing missing base feature: {col}")
            df[col] = df['URL'].apply(lambda x: extractor.extract_features(x)[col])

    X = df[desired_features]
    y = df['label']

    print(f"Features used: {desired_features}")

    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Scale
    print("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Save scaler
    joblib.dump(scaler, r'c:\Aryan\PhishingURLDetector\scaler.pkl')

    # Build Neural Network
    print("Building Neural Network...")
    model = Sequential([
        Dense(64, activation='relu', input_shape=(X_train_scaled.shape[1],)),
        BatchNormalization(),
        Dropout(0.3),
        Dense(32, activation='relu'),
        BatchNormalization(),
        Dropout(0.3),
        Dense(16, activation='relu'),
        Dense(1, activation='sigmoid')
    ])

    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy', tf.keras.metrics.Recall()])

    # Train
    print("Training model...")
    history = model.fit(
        X_train_scaled, y_train,
        epochs=10,
        batch_size=64,
        validation_split=0.2,
        verbose=1
    )

    # Evaluate
    print("Evaluating...")
    loss, accuracy, recall = model.evaluate(X_test_scaled, y_test)
    print(f"Test Accuracy: {accuracy:.4f}")
    print(f"Test Recall: {recall:.4f}")

    y_pred_prob = model.predict(X_test_scaled)
    y_pred = (y_pred_prob > 0.5).astype(int)
    
    print("\nClassification Report:\n", classification_report(y_test, y_pred))

    # Save model
    model_path = r'c:\Aryan\PhishingURLDetector\model.h5'
    model.save(model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    train()
