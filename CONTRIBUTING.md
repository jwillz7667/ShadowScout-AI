# Contributing to ShadowScout AI

## Welcome Contributors!

Thank you for considering contributing to ShadowScout AI. This document outlines the process for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct.

## How to Contribute

1. **Fork the Repository**
   ```bash
   git clone https://github.com/yourusername/ShadowScout-AI.git
   cd ShadowScout-AI
   ```

2. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Development Guidelines**
   - Follow PEP 8 style guide for Python code
   - Write meaningful commit messages
   - Add tests for new features
   - Update documentation as needed

4. **Testing**
   ```bash
   # Run tests
   pytest
   
   # Run linting
   flake8
   ```

5. **Submit a Pull Request**
   - Provide a clear description of the changes
   - Link any related issues
   - Ensure all tests pass
   - Wait for review

## Development Setup

1. **Environment Setup**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   pip install -r requirements.txt
   ```

2. **Configuration**
   - Copy `.env.example` to `.env`
   - Add required API keys and configurations

## Pull Request Process

1. Update the README.md with details of changes if needed
2. Update the documentation if you're changing functionality
3. The PR will be merged once you have the sign-off of two maintainers

## Questions?

Feel free to create an issue for any questions about contributing. 