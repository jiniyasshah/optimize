FROM python:3.14-slim
WORKDIR /app

# Install curl for healthcheck
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r requirements.txt

# Copy application code and pre-trained model
COPY service.py logging_config.py waf_model.pkl ./

# Run the service directly
CMD ["uvicorn", "service:app", "--host", "0.0.0.0", "--port", "8000"]