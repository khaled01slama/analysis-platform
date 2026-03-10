## Security Analysis Platform
A powerful all-in-one security tool that helps you find vulnerabilities, analyze software components, and get AI-powered security insights — all through an easy-to-use web dashboard.

## What It Does
Vulnerability Scanning: Finds security issues in your code using Vanir and Joern tools.

SBOM Analysis: Works with popular software bill of materials formats (SPDX, CycloneDX) to help you understand your software supply chain.

AI Security Assistant: Ask questions and get security advice powered by AI and web search.

Interactive Dashboard: Visualize results and track your security posture in real time.

Correlation Engine: Connects the dots between vulnerabilities and your code to help prioritize fixes.

Data Storage: Keeps all your analysis history in a local database.

## How It Works

The platform is made of four key parts:

SBOM Analyzer — Handles SBOM files and scans for issues.

Correlation Engine — Brings together results from different tools for a full picture.

Security Assistant — AI agent that answers your security questions.

Vanir Integration — Detects missing patches in Linux and Android systems.

## Requirements

Python 3.12+

Linux (Ubuntu/Debian recommended)

At least 8GB RAM

External tools like Grype (scanner), Ollama (AI)

Joern (for deep code analysis) and Java 11+

Bazel 8.2.1 for build 

Docker for running Grype container

## Installation Steps

cd analysis_platform

python3 -m venv venv

source venv/bin/activat

pip install -r requirements.txt

cd correlation_engine

streamlit run dashboard.py

