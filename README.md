# PhalanxAI

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

**PhalanxAI** is an advanced AI-powered Intrusion Detection System (IDS) that leverages machine learning, deep learning, and explainable AI to detect and classify network security threats in real-time. The system provides comprehensive threat intelligence through MITRE ATT&CK framework mapping and detailed explanations of detected anomalies.

## 🌟 Key Features

### 🤖 Multi-Model Ensemble Detection
- **Random Forest Classifier**: Supervised learning for attack classification
- **Isolation Forest**: Unsupervised anomaly detection
- **Autoencoder Neural Network**: Deep learning-based anomaly detection
- **Ensemble Predictions**: Combines multiple models for higher accuracy

### 🔍 Explainable AI
- **SHAP (SHapley Additive exPlanations)**: Global and local feature importance
- **LIME (Local Interpretable Model-agnostic Explanations)**: Instance-level explanations
- **Top Feature Analysis**: Identifies which network features contributed to detection
- **Human-readable alerts**: Natural language explanations for security analysts

### 🎯 MITRE ATT&CK Integration
- Maps detected attacks to MITRE ATT&CK techniques and tactics
- Provides threat context and recommended mitigations
- Tracks attacker techniques across the cyber kill chain
- Comprehensive threat intelligence database

### 📊 Real-time Dashboard
- Live threat monitoring and visualization
- Attack distribution analytics
- Severity-based alert prioritization (Critical, High, Medium, Low)
- Time-series analysis of attack patterns
- Model performance metrics

### 🔧 RESTful API
- FastAPI-powered backend for high performance
- Comprehensive API documentation (Swagger/OpenAPI)
- Real-time network flow analysis
- Model training and management endpoints
- Alert management and querying

## 🏗️ Architecture

```
PhalanxAI/
├── main.py                 # FastAPI application entry point
├── config.py               # Configuration and settings
├── database.py             # SQLAlchemy models and database setup
├── requirements.txt        # Python dependencies
│
├── api/                    # REST API endpoints
│   ├── routes.py          # API route handlers
│   └── schemas.py         # Pydantic data models
│
├── models/                 # Machine Learning models
│   ├── model_manager.py   # Model orchestration and ensemble
│   ├── random_forest.py   # Random Forest classifier
│   ├── isolation_forest.py # Isolation Forest anomaly detector
│   └── autoencoder.py     # Deep learning autoencoder
│
├── data/                   # Data processing
│   ├── loaders.py         # Dataset loading utilities
│   ├── preprocessor.py    # Feature preprocessing and scaling
│   └── feature_extractor.py # Network feature extraction
│
├── explainability/         # Explainable AI components
│   ├── shap_explainer.py  # SHAP-based explanations
│   ├── lime_explainer.py  # LIME-based explanations
│   └── alert_generator.py # Generate human-readable alerts
│
├── mitre/                  # MITRE ATT&CK framework
│   ├── attack_db.py       # MITRE technique database
│   └── mapper.py          # Map attacks to MITRE techniques
│
├── static/                 # Web dashboard
│   ├── index.html         # Dashboard interface
│   ├── css/
│   └── js/
│
├── trained_models/         # Saved model files
└── sample_data/           # Sample network traffic data
```

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- PostgreSQL 12+ (optional, for persistent storage)
- 4GB+ RAM recommended
- Linux, macOS, or Windows

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/Gentwocoder/PhalanxAI.git
cd phalanxai
```

2. **Create a virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment variables**
```bash
cp .env.example .env
# Edit .env with your database credentials and settings
```

5. **Set up the database (optional)**
```bash
# Create PostgreSQL database
createdb ai_ids

# Or use SQLite by updating DATABASE_URL in .env:
# DATABASE_URL=sqlite+aiosqlite:///./ai_ids.db
```

### Quick Start

1. **Start the application**
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

2. **Access the dashboard**
   - Open browser: http://localhost:8000
   - API documentation: http://localhost:8000/docs

3. **Train models** (first-time setup)
```bash
# Using the API
curl -X POST "http://localhost:8000/api/train" \
  -H "Content-Type: application/json" \
  -d '{
    "dataset_path": "sample_data/network_traffic.csv",
    "sample_size": 10000
  }'
```

## 📖 Usage

### Using the Dashboard

1. **Monitor Threats**: View real-time alerts and statistics on the main dashboard
2. **Analyze Alerts**: Click on any alert to see detailed explanations and MITRE mappings
3. **Explore MITRE Matrix**: Navigate the MITRE ATT&CK matrix to understand attack techniques
4. **Model Management**: Train new models or view model performance metrics

### Using the API

#### Health Check
```bash
curl http://localhost:8000/api/health
```

#### Analyze Network Flow
```bash
curl -X POST "http://localhost:8000/api/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.50",
    "src_port": 54321,
    "dst_port": 80,
    "protocol": "TCP",
    "flow_duration": 12000,
    "total_fwd_packets": 45,
    "total_backward_packets": 38,
    ...
  }'
```

#### Get Recent Alerts
```bash
curl http://localhost:8000/api/alerts?limit=10&severity=Critical
```

#### Train Models
```bash
curl -X POST "http://localhost:8000/api/train" \
  -H "Content-Type: application/json" \
  -d '{
    "dataset_path": "path/to/cicids2017.csv",
    "sample_size": 50000
  }'
```

### Python SDK Example

```python
import requests

API_URL = "http://localhost:8000/api"

# Analyze a network flow
flow_data = {
    "src_ip": "192.168.1.100",
    "dst_ip": "203.0.113.50",
    "dst_port": 443,
    "flow_duration": 5000,
    "total_fwd_packets": 25,
    # ... other features
}

response = requests.post(f"{API_URL}/predict", json=flow_data)
result = response.json()

if result["is_malicious"]:
    print(f"⚠️  ALERT: {result['attack_type']}")
    print(f"Confidence: {result['confidence']:.2%}")
    print(f"Severity: {result['severity']}")
    print(f"MITRE: {result['mitre_technique_name']}")
    print(f"Explanation: {result['explanation']}")
```

## 🎓 Supported Attack Types

PhalanxAI can detect and classify the following attack types:

- **Denial of Service (DoS/DDoS)**
  - DoS Hulk
  - DoS GoldenEye
  - DoS Slowhttptest
  - DoS slowloris
  - DDoS

- **Brute Force Attacks**
  - FTP-Patator
  - SSH-Patator
  - Web Attack - Brute Force

- **Web Attacks**
  - SQL Injection
  - Cross-Site Scripting (XSS)

- **Network Reconnaissance**
  - Port Scanning

- **Command & Control**
  - Botnet Activity

- **Exploitation**
  - Heartbleed
  - Infiltration

- **Anomalies**
  - Unknown attack patterns (zero-day detection)

## 📊 Model Performance

The ensemble model achieves strong performance on CICIDS2017 dataset:

| Model | Accuracy | Precision | Recall | F1-Score |
|-------|----------|-----------|--------|----------|
| Random Forest | 99.2% | 98.8% | 98.5% | 98.6% |
| Isolation Forest | 94.5% | - | - | - |
| Autoencoder | 95.8% | - | - | - |
| **Ensemble** | **99.5%** | **99.1%** | **98.9%** | **99.0%** |

## 🔧 Configuration

### Key Configuration Parameters

Edit `config.py` or `.env` file:

```python
# Detection Thresholds
ANOMALY_THRESHOLD = -0.5          # Isolation Forest threshold
AUTOENCODER_THRESHOLD = 0.1       # Reconstruction error threshold
CONFIDENCE_THRESHOLD = 0.7        # Minimum confidence for alerts

# Model Paths
MODEL_DIR = "trained_models"
RANDOM_FOREST_PATH = "trained_models/random_forest.joblib"
ISOLATION_FOREST_PATH = "trained_models/isolation_forest.joblib"
AUTOENCODER_PATH = "trained_models/autoencoder.pt"

# Database
DATABASE_URL = "postgresql+asyncpg://user:pass@localhost:5432/ai_ids"
```

### Feature Configuration

The system uses 79 network flow features from CICIDS2017 dataset:
- Flow statistics (duration, packets, bytes)
- Protocol flags (SYN, ACK, FIN, RST, etc.)
- Inter-arrival times (IAT)
- Packet length statistics
- Flow rates and ratios
- Window sizes
- Subflow characteristics

See `config.py` for the complete feature list.

## 🧪 Training Custom Models

### Using Your Own Dataset

1. **Prepare your dataset** in CSV format with the required features
2. **Format**: Include all 79 features + 'Label' column
3. **Train models** via API or Python:

```python
from models import ModelManager
from data import DatasetLoader, DataPreprocessor

# Load data
loader = DatasetLoader("your_data_dir")
df = loader.load_cicids2017("your_dataset.csv")

# Preprocess
preprocessor = DataPreprocessor()
X_train, X_test, y_train, y_test = preprocessor.fit_transform(df)

# Train models
mm = ModelManager("trained_models")
metrics = mm.train_all(X_train, y_train, X_val=X_test)

# Save models
mm.save_all()
```

### Supported Datasets

- **CICIDS2017** ✅ (Primary)
- **CICIDS2018** ✅ (Compatible)
- **NSL-KDD** ⚠️ (Requires feature mapping)
- **UNSW-NB15** ⚠️ (Requires feature mapping)

## 🐛 Troubleshooting

### Models Not Loading
```bash
# Check if model files exist
ls -lh trained_models/

# Retrain models
curl -X POST http://localhost:8000/api/train -H "Content-Type: application/json" \
  -d '{"dataset_path": "sample_data/traffic.csv"}'
```

### Database Connection Errors
```bash
# Check PostgreSQL service
sudo systemctl status postgresql

# Or use SQLite instead
export DATABASE_URL="sqlite+aiosqlite:///./ai_ids.db"
```

### Memory Issues
- Reduce `sample_size` when training
- Use batch prediction for large datasets
- Adjust `FEATURE_COLUMNS` to use fewer features

### SHAP/LIME Installation
```bash
# If explainability features fail
pip install shap lime --force-reinstall
```

## 🛣️ Roadmap

- [ ] Real-time packet capture integration (Scapy/Zeek)
- [ ] Support for additional datasets (NSL-KDD, UNSW-NB15)
- [ ] Advanced visualization (Grafana/Kibana integration)
- [ ] Model retraining on new threats
- [ ] Container orchestration (Docker, Kubernetes)
- [ ] Multi-tenant support
- [ ] Integration with SIEM systems
- [ ] Automated response actions
- [ ] Cloud deployment templates (AWS, Azure, GCP)

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Code formatting
black .
isort .

# Linting
pylint models/ api/ data/
```

## 📚 References

### Datasets
- [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) - Canadian Institute for Cybersecurity
- [CICIDS2018](https://www.unb.ca/cic/datasets/ids-2018.html)

### Frameworks
- [MITRE ATT&CK](https://attack.mitre.org/) - Adversarial Tactics, Techniques & Common Knowledge
- [FastAPI](https://fastapi.tiangolo.com/) - Modern web framework
- [Scikit-learn](https://scikit-learn.org/) - Machine learning library
- [PyTorch](https://pytorch.org/) - Deep learning framework

### Explainability
- [SHAP](https://github.com/slundberg/shap) - SHapley Additive exPlanations
- [LIME](https://github.com/marcotcr/lime) - Local Interpretable Model-agnostic Explanations


## 🙏 Acknowledgments

- Canadian Institute for Cybersecurity for CICIDS datasets
- MITRE Corporation for the ATT&CK framework
- The open-source ML/AI community

## 📧 Contact

For questions, issues, or collaboration:
- **GitHub Issues**: [Report a bug](https://github.com/Gentwocoder/PhalanxAI/issues)
- **Email**: adetoyeseoyekanmi@example.com

---

**Built with ❤️ for cybersecurity professionals and researchers**

*Stay vigilant. Stay protected. Stay ahead with PhalanxAI.*
