FROM python:latest
COPY . /app
WORKDIR /app
ADD requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY app.py app.py
CMD ["python", "-u", "app.py"]
ENV FLASK_APP app.py
ENV FLASK_RUN_HOST 0.0.0.0