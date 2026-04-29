FROM python:3.10

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir \
    pandas \
    scikit-learn \
    flask \
    mysql-connector-python

ENV PORT=8080

EXPOSE 8080

CMD ["python", "app.py"]