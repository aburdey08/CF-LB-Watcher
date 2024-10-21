FROM python:3.9.20-slim

LABEL maintainer="Andrew Burdey <a.burdey08@gmail.com>"
LABEL version="1.3.1"
LABEL description="Cloudflare Load Balancer Watcher - monitors nodes and manages DNS via Cloudflare API"
LABEL repository="https://github.com/aburdey08/CF-LB-Watcher"

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY cf_lb_watcher.py .

EXPOSE 8080

CMD ["python", "cf_lb_watcher.py"]