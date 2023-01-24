FROM python:3

LABEL maintainer="Christopher Goes <ghostofgoes@gmail.com>"
LABEL project_url="https://github.com/GhostofGoes/getmac"

ADD .. /opt/getmac
WORKDIR /opt/getmac

RUN python -m pip install .

ENTRYPOINT ["getmac"]
