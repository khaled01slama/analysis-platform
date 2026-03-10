# SBOM Analyzer

A tool for analyzing Software Bill of Materials (SBOM) files.

## Features

- Support for multiple SBOM formats:
  - SPDX (2.2 and 2.3)
  - CycloneDX
- Format conversion capabilities:
  - Convert between SPDX versions (2.2 and 2.3)
  - Convert CycloneDX to SPDX 2.2/2.3
  - Support for various input formats:
    - JSON
    - XML
    - YAML
    - RDF
    - Tag-value format
- SBOM analysis and vulnerability reporting
- Web interface for file upload and analysis

## Prerequisites

- Python 3.12+
- pip
- virtualenv (recommended)
- Grype vulnerability scanner

## Installation

1. Create a virtual environment:
```bash
python -m venv spdx-env
source spdx-env/bin/activate  # On Linux/Mac
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install Grype:
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b ~/.local/bin
```

## Usage

### Format Conversion

Convert between SBOM formats using the converter:

```bash
python spdx22_converter.py <input_file> [output_file] [target_version]
```

Arguments:
- `input_file`: Path to input SBOM file (SPDX or CycloneDX)
- `output_file`: (Optional) Path for output file. Default: input filename with .spdx extension
- `target_version`: (Optional) Target SPDX version - either "SPDX-2.2" or "SPDX-2.3". Default: "SPDX-2.2"

Example:
```bash
python spdx22_converter.py input.cdx output.spdx SPDX-2.2
```

### SBOM Analysis

Analyze an SBOM file:

```bash
python main.py <input_file>
```

### Web Interface

Run the web application:

```bash
python app.py
```

Then open http://localhost:5000 in your browser.

3. Upload an SBOM file (SPDX or JSON format)

4. View analysis results in the interactive dashboard

5. Export results in your preferred format

## Supported Input Formats

### SPDX
- JSON
- XML/RDF
- Tag-value format
- YAML

### CycloneDX
- JSON
- XML
- YAML

## Output Format

The converter outputs SPDX documents in standard SPDX format (2.2 or 2.3 as specified) while preserving all possible metadata from the input file.

## Project Structure

```
.
├── app.py              # Flask web application
├── analyzer.py         # SBOM analysis logic
├── converter.py        # SPDX to JSON converter
├── requirements.txt    # Python dependencies
├── static/            # Static assets (CSS, JS)
├── templates/         # HTML templates
└── uploads/          # Uploaded files directory
```

## Troubleshooting

If you encounter parser-related performance issues:
- The application uses LALR parser table caching to improve performance
- Cache files are stored in the parsetab directory
- Clear the cache if you experience parsing issues

## Contributing

1. Fork the repository
2. Create your feature branch
3. Submit a pull request

## License

[Insert your license information here]