FROM python:3.7-alpine

ENV FLASK_APP app.py
ENV FLASK_RUN_HOST 0.0.0.0
ENV FLASK_RUN_PORT 80
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
RUN apk add --no-cache gcc musl-dev linux-headers openssl-dev libffi-dev
CMD ["app.py"]