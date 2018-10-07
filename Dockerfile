FROM python:3

ADD . /opt/getmac
WORKDIR /opt/getmac

RUN python setup.py install

ENTRYPOINT ["getmac"]
