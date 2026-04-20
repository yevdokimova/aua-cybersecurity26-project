FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY demo/requirements.txt demo/requirements.txt
RUN pip install --no-cache-dir -r demo/requirements.txt

COPY sqlshield/ sqlshield/
COPY demo/ demo/

ENV PYTHONPATH=/app

EXPOSE 8000

CMD ["python", "demo/app.py"]
