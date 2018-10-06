FROM python:3

ADD . /opt/get-mac
WORKDIR /opt/get-mac

RUN python setup.py install

ENTRYPOINT ["get-mac"]
