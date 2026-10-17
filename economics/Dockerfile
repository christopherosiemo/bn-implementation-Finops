FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY economics/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home worker
COPY economics/autopilot ./autopilot
USER 10001:10001
EXPOSE 8000
CMD ["python", "-m", "autopilot.server"]
