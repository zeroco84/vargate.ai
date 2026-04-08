FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

RUN addgroup --system vargate && adduser --system --ingroup vargate vargate
RUN mkdir -p /data/archive && chown -R vargate:vargate /app /data
USER vargate

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info"]
