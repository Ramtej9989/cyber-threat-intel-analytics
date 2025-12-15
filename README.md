# 🚨 Cyber Threat Intelligence & SOC Analytics – Backend

A FastAPI-based backend system that simulates real-world Security Operations Center (SOC) workflows.  
This service ingests security logs, correlates threat intelligence, generates alerts, and calculates entity risk scores.

---

## 🌐 Live Deployment

API URL  
https://cyber-threat-intel-analytics.onrender.com

---

## 🎯 Project Objective

To build a realistic cyber security analytics backend that mirrors how modern SOC platforms:
- Ingest logs
- Detect suspicious activity
- Generate alerts
- Enrich data with threat intelligence
- Compute entity risk scores

This project is designed for learning, demonstrations, and portfolio showcasing.

---

## 🧠 Core Features

- Network and authentication log ingestion
- Automated alert generation
- Threat intelligence enrichment
- Entity risk scoring (Users, IPs, Hosts)
- API key–based security
- CORS-enabled frontend communication
- Scalable FastAPI architecture

---

## 🛠️ Tech Stack

Backend Framework: FastAPI  
Language: Python 3.11  
Database: MongoDB Atlas  
Data Processing: Pandas, NumPy  
Machine Learning Utilities: Scikit-learn  
Server: Uvicorn  
Hosting: Render

---

## 📂 Project Structure

cyber-threat-intel-analytics/
├── main.py
├── app/
│   ├── database.py
│   ├── models/
│   ├── routes/
│   │   ├── alerts.py
│   │   ├── logs.py
│   │   ├── entities.py
│   │   └── threat_intel.py
│   ├── services/
│   └── utils/
├── requirements.txt
└── README.md

---

## ⚙️ Environment Variables

Configure the following environment variables in Render:

PYTHON_VERSION=3.11.9  
MONGODB_URI=your_mongodb_connection_string  
MONGODB_DB=soc_platform  
API_KEY=your_secure_api_key  
FRONTEND_URL=https://cyber-threat-intel-frontend.vercel.app

---

## 🔐 CORS Configuration

CORS is enabled to allow secure frontend communication:

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_URL")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
