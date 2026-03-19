FROM python:3.10.12

WORKDIR /app

# For docker layer caching, any changes to the python code
# Will not affect the cached pip install layer
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 5001

ENTRYPOINT [ "python3" , "app_vul.py" ]
