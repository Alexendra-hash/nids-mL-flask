# 🛡️ Machine Learning Network Intrusion Detection System (NIDS)

A Flask-based Network Intrusion Detection System that uses a Random Forest classifier to detect and log malicious network traffic in real time, with results stored in MySQL and automatic email alerts on detected intrusions.

## 📌 Overview
This project applies machine learning to network security by training a classification model on the NSL-KDD dataset to distinguish normal traffic from various attack types. The trained model is deployed through a Flask web application that classifies incoming traffic, logs results to a MySQL database, and sends automated email alerts when an intrusion is detected.

## ⚙️ Features
- Random Forest-based traffic classification
- Trained and evaluated on the NSL-KDD dataset (KDDTrain.txt)
- Flask web interface for interacting with the model
- MySQL integration for logging detection results
- Automatic email alerts for detected intrusions
- Model evaluation visuals: confusion matrix, feature importance, and model comparison

## 🗂️ Project Structure
## 🧠 Model
- **Algorithm:** Random Forest Classifier
- **Dataset:** NSL-KDD
- **Evaluation:** Confusion matrix and model comparison against baseline classifiers (see visuals above)

## 🚀 How It Works
1. Network traffic features are fed into the trained Random Forest model
2. The model classifies traffic as normal or malicious
3. Results are logged to a MySQL database
4. If an intrusion is detected, an automated email alert is triggered

## 🛠️ Tech Stack
- **Language:** Python
- **Framework:** Flask
- **ML Library:** scikit-learn
- **Database:** MySQL
- **Notebook:** Jupyter

## 📈 Future Improvements
- Real-time packet capture integration (e.g., with Scapy or Wireshark)
- Deployment to cloud (AWS/Azure) for live monitoring
- Model retraining pipeline for evolving attack patterns
- Dashboard for visualizing live traffic and alerts

## 👩‍💻 Author
**Alexendra-hash** — Dental Therapist & CS graduate with a growing focus on cybersecurity and digital health.