# 🛡️ AI-Powered Phishing Detection System

A full-stack machine learning system that detects phishing URLs, emails, and websites in real-time using advanced NLP and ML models.

---

## 📁 Project Structure

```
phishing-detection-ai/
├── frontend/          # React.js dashboard UI
├── backend/           # Node.js + Express API server
├── ml/                # Python ML model training & inference
├── docs/              # API documentation & architecture diagrams
├── docker-compose.yml
└── README.md
```

---

## 🚀 Features

- **Real-time URL Analysis** — Scan any URL for phishing indicators
- **Email Header Analysis** — Detect spoofed senders & suspicious patterns
- **ML-based Scoring** — Confidence scores with explainability
- **Dashboard** — Visual analytics & threat history
- **REST API** — Integrate into any application
- **Batch Scanning** — Analyze multiple URLs/emails at once

---

## 🧠 ML Models Used

| Model | Task | Accuracy |
|-------|------|----------|
| Random Forest | URL feature classification | 97.2% |
| BERT (fine-tuned) | Email body NLP analysis | 94.8% |
| LSTM | Sequential pattern detection | 93.1% |

---

## ⚙️ Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React.js, TailwindCSS, Recharts |
| Backend | Node.js, Express.js |
| ML Service | Python, FastAPI, scikit-learn |
| Database | PostgreSQL + Redis (cache) |
| Deployment | Docker, Docker Compose |

---

## 🏁 Quick Start

### Prerequisites
- Node.js >= 18
- Python >= 3.10
- Docker & Docker Compose

### 1. Clone & Setup
```bash
git clone https://github.com/yourname/phishing-detection-ai.git
cd phishing-detection-ai
```

### 2. Environment Variables
```bash
cp backend/.env.example backend/.env
cp ml/.env.example ml/.env
# Fill in your values
```

### 3. Run with Docker
```bash
docker-compose up --build
```

### 4. Run Manually (Dev Mode)
```bash
# Terminal 1 - ML Service
cd ml && pip install -r requirements.txt && uvicorn app:app --port 8000

# Terminal 2 - Backend
cd backend && npm install && npm run dev

# Terminal 3 - Frontend
cd frontend && npm install && npm start
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan/url` | Scan a single URL |
| POST | `/api/scan/email` | Analyze email content |
| POST | `/api/scan/batch` | Bulk scan (up to 100 items) |
| GET | `/api/history` | Get scan history |
| GET | `/api/stats` | Dashboard statistics |
| GET | `/api/health` | Health check |

---

## 📊 Sample API Response

```json
{
  "url": "http://secure-bank-login.xyz/verify",
  "is_phishing": true,
  "confidence": 0.97,
  "risk_score": 94,
  "risk_level": "CRITICAL",
  "indicators": [
    "Suspicious TLD (.xyz)",
    "Brand impersonation detected (bank)",
    "No HTTPS certificate",
    "Domain registered < 30 days ago",
    "IP-based redirect detected"
  ],
  "scanned_at": "2024-01-15T10:30:00Z"
}
```

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -m 'Add your feature'`
4. Push and open a PR

---

## 📜 License

MIT License — see [LICENSE](LICENSE) file.
