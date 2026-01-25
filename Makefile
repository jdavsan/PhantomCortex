# PhantomCortex Makefile
# Common development commands

.PHONY: help install test lint format clean docker run

help:
	@echo "PhantomCortex - Available commands:"
	@echo ""
	@echo "  make install       - Install dependencies"
	@echo "  make install-dev   - Install dev dependencies"
	@echo "  make test          - Run unit tests"
	@echo "  make test-cov      - Run tests with coverage"
	@echo "  make lint          - Run code linters"
	@echo "  make format        - Format code with black"
	@echo "  make clean         - Clean temporary files"
	@echo "  make docker-build  - Build Docker image"
	@echo "  make docker-run    - Run with Docker Compose"
	@echo "  make run           - Run threat collection"
	@echo "  make setup         - Complete setup (install + translation)"
	@echo ""

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements-dev.txt

test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=core --cov=modules --cov-report=html --cov-report=term

lint:
	flake8 core/ modules/ --max-line-length=100 --statistics
	pylint core/ modules/ || true

format:
	black core/ modules/ tests/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .coverage htmlcov/

docker-build:
	docker build -t phantomcortex:latest .

docker-run:
	docker-compose up -d

docker-stop:
	docker-compose down

docker-logs:
	docker-compose logs -f

run:
	python core/collector.py

run-translate:
	python modules/translator.py

run-alert:
	python modules/alerting.py --test

run-report:
	python modules/reporting.py

setup:
	@echo "Setting up PhantomCortex..."
	pip install -r requirements.txt
	python scripts/setup_translation.py
	@echo "✅ Setup complete!"
	@echo ""
	@echo "Next steps:"
	@echo "  1. cp config/config.example.yaml config/config.yaml"
	@echo "  2. Edit config/config.yaml with your settings"
	@echo "  3. make run"

verify:
	python scripts/verify_publication.py

.DEFAULT_GOAL := help
