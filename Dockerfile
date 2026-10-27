FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080 ATJM_DATA_DIR=/data
WORKDIR /app
COPY app.py audit_ledger.py index.html ./
EXPOSE 8080
CMD ["python", "app.py"]
