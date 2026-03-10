# Vanir Agent

An intelligent agent that leverages Vanir for detecting and analyzing missing security patches in code repositories.

## Overview

Vanir Agent provides a user-friendly interface to Vanir, a source code-based static analysis tool developed by Google that automatically identifies missing security patches in target systems.

This agent enhances Vanir's capabilities with:

1. **Interactive Web Interface** - A Streamlit web application for easy interaction with Vanir 
2. **Code Context Analysis** - Extraction of relevant code surrounding vulnerable sections
3. **Scanning Tools** - Multiple specialized scanners for different use cases

## Installation

### Prerequisites

- Python 3.9 or higher
- Vanir installed and built (See [Vanir Installation](#vanir-installation))

### Install the package

```bash
# Clone the repository
git clone https://github.com/yourusername/vanir_agent.git
cd vanir_agent

# Install the package
pip install -e .
```

### Vanir Installation

Vanir Agent requires an installation of Vanir. Follow these steps to install Vanir:

1. Install the prerequisites:
   ```bash
   sudo apt install git openjdk-11-jre bazel
   ```

2. Clone the Vanir repository:
   ```bash
   git clone https://github.com/google/vanir.git
   cd vanir
   ```

3. Build the detector runner:
   ```bash
   bazel build //:detector_runner --build_python_zip -c opt
   ```

4. Set the `VANIR_PATH` environment variable:
   ```bash
   export VANIR_PATH=/path/to/vanir
   ```

## Usage

### Running the Web Interface

The Vanir Agent provides a Streamlit web application for easy interaction:

```bash
# Navigate to the project directory
cd vanir_agent

# Run the Streamlit app
streamlit run app.py
```

This will open a web browser with the Vanir Agent interface.

### Using the Web Interface

The web interface provides two main pages:

1. **Scanner** - Configure and run Vanir scans on repositories
2. **Results** - View detailed results of scans and analyze code context

### Programmatic Usage

You can also use the Vanir Agent programmatically:

```python
from vanir_agent import VanirAgent

# Initialize the agent
agent = VanirAgent()

# Scan a repository
result = agent.scan_repository(
    repository_path="/path/to/repo",
    ecosystem="Android",
    target_strategy="truncated_path_match"
)

# Extract code context
context = agent.extract_code_context(
    file_path="/path/to/file.java",
    vulnerability_id="CVE-2023-12345"
)
```

## Features

### Vanir Scanner Tool

- Scans repositories for missing security patches
- Supports different scanning strategies (truncated_path_match, exact_path_match, all_files)
- Generates detailed reports in JSON and HTML formats

### Code Context Extractor Tool

- Extracts relevant code sections around vulnerable code
- Provides context to understand the vulnerability
- Helps with assessing the impact and developing fixes

### Scanner Tools

- Supports multiple scanner types:
  - Repository Scanner
  - Package Scanner
  - Android Kernel Scanner
  - Offline Directory Scanner
- Provides detailed reports in JSON and HTML formats
- Configurable scanning strategies and filters

## Screenshots

### Scanner Page
![Scanner Page](https://raw.githubusercontent.com/google/vanir/main/docs/images/vanir_macro_arch.png)

### Results Page
![Results Page](https://raw.githubusercontent.com/google/vanir/main/docs/images/vanir_detector_report.png)

## License

This project is licensed under the BSD License - see the LICENSE file for details.

## Acknowledgments

- Vanir is developed by Google: [github.com/google/vanir](https://github.com/google/vanir)
- This agent enhances Vanir's capabilities with additional tools and interfaces