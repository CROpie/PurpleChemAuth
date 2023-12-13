FROM python:3.10-alpine

WORKDIR /code

COPY ./requirements.txt /code/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY ./auth_app /code/auth_app

CMD ["uvicorn", "auth_app.main:app", "--host", "0.0.0.0", "--port", "81"]