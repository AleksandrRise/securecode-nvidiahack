# 🧩 PatchFrame

**Real-Time Patch-Level Vulnerability Scanner for Open Source Dependencies**

PatchFrame goes beyond traditional security scanners by analyzing dependencies at the patch level, detecting vulnerabilities that exist in your current version but haven't been assigned CVEs yet. It provides real-time scanning, trust scoring, anomaly detection, and comprehensive reporting.

## 🚀 Features

### Core Capabilities
- **🔍 Patch-Level Analysis**: Scans dependencies down to individual git commits and patches
- **⚡ Real-Time Detection**: Identifies vulnerabilities before they're officially reported as CVEs
- **🔒 Trust Scoring**: Evaluates maintainer reputation and patch trustworthiness
- **🚨 Anomaly Detection**: Flags suspicious patterns in dependency code changes
- **📊 SBOM Generation**: Creates Software Bill of Materials in multiple formats (SPDX, CycloneDX, SWID)
- **📈 Interactive Dashboard**: Beautiful web interface for visualizing scan results

### Advanced Features
- **🌐 Multi-Package Support**: npm, pip, cargo, composer, Gemfile, go.mod
- **🔧 AST Analysis**: Uses Tree-sitter for deep code analysis
- **📧 Notifications**: Email, Slack, and Teams integration
- **🔄 Continuous Monitoring**: API endpoints for integration with CI/CD pipelines
- **📋 Comprehensive Reporting**: JSON, table, and summary output formats

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- Git
- Node.js (for Tree-sitter grammars)

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/patchframe.git
   cd patchframe
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Initialize the database**
   ```bash
   python -m patchframe.cli.main init
   ```

4. **Install Tree-sitter grammars** (optional but recommended)
   ```bash
   git clone https://github.com/tree-sitter/tree-sitter-javascript vendor/tree-sitter-javascript
   git clone https://github.com/tree-sitter/tree-sitter-python vendor/tree-sitter-python
   ```

## 🚀 Usage

### Command Line Interface

#### Basic Scan
```bash
# Scan a project for vulnerabilities
patchframe scan /path/to/your/project

# Save results to file
patchframe scan /path/to/your/project --output results.json

# Display results in table format
patchframe scan /path/to/your/project --format table
```

#### Advanced Scanning
```bash
# Include trust analysis and anomaly detection
patchframe scan /path/to/your/project --trust --anomaly

# Generate SBOM with scan
patchframe scan /path/to/your/project --sbom --sbom-format spdx

# Limit commit analysis depth
patchframe scan /path/to/your/project --max-commits 50
```

#### Trust Score Analysis
```bash
# Analyze trust score for a specific patch
patchframe trust lodash 1.2.3 abc1234 --author john@example.com
```

#### Anomaly Detection
```bash
# Detect anomalies in a patch
patchframe anomaly lodash abc1234 --diff-file patch.diff
```

#### SBOM Generation
```bash
# Generate SBOM in different formats
patchframe sbom /path/to/your/project --format cyclonedx
patchframe sbom /path/to/your/project --format spdx --validate
```

### API Usage

#### Start a Scan
```bash
curl -X POST "http://localhost:8000/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "project_path": "/path/to/project",
    "max_commits": 100,
    "include_dev_dependencies": true,
    "scan_depth": "medium"
  }'
```

#### Get Scan Status
```bash
curl "http://localhost:8000/api/v1/scan/{scan_id}"
```

#### Calculate Trust Score
```bash
curl -X POST "http://localhost:8000/api/v1/trust" \
  -H "Content-Type: application/json" \
  -d '{
    "dependency_name": "lodash",
    "patch_sha": "abc1234",
    "author_email": "john@example.com"
  }'
```

### Web Dashboard

1. **Start the API server**
   ```bash
   python -m patchframe.api.main
   ```

2. **Open the dashboard**
   Navigate to `http://localhost:8000/static/dashboard.html`

## 🔧 Configuration

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost/patchframe

# GitHub API (for enhanced trust scoring)
GITHUB_TOKEN=your_github_token

# SMTP Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password

# Webhook URLs
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
TEAMS_WEBHOOK_URL=https://your-org.webhook.office.com/...

# Notification Settings
NOTIFICATION_THRESHOLD=medium  # low, medium, high, critical
```

### Configuration File

Create `config.yaml` in your project root:

```yaml
# Scan Configuration
scan:
  max_commits: 100
  include_dev_dependencies: true
  scan_depth: medium  # quick, medium, deep

# Trust Analysis
trust:
  enabled: true
  github_token: ${GITHUB_TOKEN}

# Anomaly Detection
anomaly:
  enabled: true
  thresholds:
    low: 0.3
    medium: 0.5
    high: 0.7
    critical: 0.9

# Notifications
notifications:
  email:
    enabled: true
    recipients: ["security@company.com"]
  slack:
    enabled: true
    channel: "#security-alerts"
  teams:
    enabled: false

# SBOM Generation
sbom:
  default_format: spdx
  include_vulnerabilities: true
```

## 📊 Understanding Results

### Vulnerability Severity Levels

- **🔴 Critical**: Immediate action required, high risk of exploitation
- **🟠 High**: Significant security risk, should be addressed soon
- **🟡 Medium**: Moderate risk, review and plan remediation
- **🟢 Low**: Minimal risk, monitor for changes

### Trust Score Interpretation

- **0.8-1.0**: High trust - Well-established maintainer, verified email
- **0.6-0.8**: Moderate trust - Some positive indicators
- **0.4-0.6**: Low trust - Limited trust indicators
- **0.0-0.4**: Very low trust - Exercise caution

### Anomaly Detection

The anomaly detector looks for:
- Obfuscated or minified code
- Dangerous functions (eval, Function constructor)
- Suspicious patterns (base64 encoding, large binary content)
- Unusual file size changes
- Suspicious comments or keywords

## 🔌 Integration

### GitHub Actions

```yaml
name: PatchFrame Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      
      - name: Install PatchFrame
        run: |
          pip install patchframe
      
      - name: Run Security Scan
        run: |
          patchframe scan . --format json --output scan-results.json
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-scan-results
          path: scan-results.json
```

### CI/CD Pipeline

```bash
# Example for Jenkins pipeline
stage('Security Scan') {
    steps {
        sh 'pip install patchframe'
        sh 'patchframe scan . --format json --output results.json'
        archiveArtifacts artifacts: 'results.json'
        
        script {
            def results = readJSON file: 'results.json'
            def criticalVulns = results.summary.critical_vulns
            
            if (criticalVulns > 0) {
                error "Found ${criticalVulns} critical vulnerabilities!"
            }
        }
    }
}
```

## 🏗️ Architecture

```
patchframe/
├── core/                 # Core scanning logic
│   └── scanner.py       # Main scanner implementation
├── api/                 # FastAPI web interface
│   ├── main.py         # API endpoints
│   └── models.py       # Pydantic models
├── services/           # Additional services
│   ├── trust_scorer.py    # Trust analysis
│   ├── anomaly_detector.py # Anomaly detection
│   ├── sbom_generator.py  # SBOM generation
│   └── notification_service.py # Notifications
├── cli/                # Command-line interface
│   └── main.py        # CLI commands
├── database/           # Database models
│   └── models.py      # SQLAlchemy models
└── static/            # Web assets
    └── dashboard.html # Interactive dashboard
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

1. **Fork and clone the repository**
2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. **Install development dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```
4. **Run tests**
   ```bash
   pytest
   ```
5. **Start development server**
   ```bash
   python -m patchframe.api.main --reload
   ```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Tree-sitter](https://tree-sitter.github.io/tree-sitter/) for AST parsing
- [D3.js](https://d3js.org/) for data visualization
- [FastAPI](https://fastapi.tiangolo.com/) for the web framework
- [Rich](https://rich.readthedocs.io/) for beautiful CLI output

## 📞 Support

- **Documentation**: [docs.patchframe.io](https://docs.patchframe.io)
- **Issues**: [GitHub Issues](https://github.com/your-org/patchframe/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/patchframe/discussions)
- **Email**: support@patchframe.io

## 🔮 Roadmap

- [ ] VS Code extension for inline vulnerability annotations
- [ ] Integration with more package managers (Maven, Gradle, etc.)
- [ ] Machine learning-based vulnerability prediction
- [ ] Real-time monitoring and alerting
- [ ] Integration with vulnerability databases (NVD, OSV)
- [ ] Support for container image scanning
- [ ] Automated remediation suggestions

---

**Made with ❤️ by the PatchFrame Team** 