# Start from an official Python 3.12 image (slim = smaller, no extras)
FROM python:3.12-slim

# All following commands run inside this folder in the container
WORKDIR /app

# Copy requirements FIRST, before the app code (explained below)
COPY requirements.txt .

# Install dependencies into the container
RUN pip install --no-cache-dir -r requirements.txt

# Now copy the application code
COPY main.py .

# Document that the app uses port 9090
EXPOSE 9090

# The command that runs when the container starts
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9090"]