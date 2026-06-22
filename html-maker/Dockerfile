FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY html_maker.py .

CMD ["python", "-u", "html_maker.py"]
