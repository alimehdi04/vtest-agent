# vtest pytest sandbox image: localhost/vtest-pytest:1
# Runs repository code and LLM-generated tests. Base image pinned by digest.
FROM docker.io/library/python:3.14-slim@sha256:ec6a14df5b63e3fbb3498e3240f7f640c230f9dca67683d23265db3866697f2d

COPY pytest-requirements.txt /opt/vtest/pytest-requirements.txt
# Builds run with --cap-drop=ALL, so useradd (which needs CAP_CHOWN for /etc/shadow)
# isn't available. Append the unprivileged user directly instead.
RUN python3 -m pip install --no-cache-dir --disable-pip-version-check --no-input \
      --root-user-action=ignore --require-hashes --only-binary=:all: --no-deps \
      -r /opt/vtest/pytest-requirements.txt \
 && echo 'sandbox:x:10001:10001:vtest sandbox:/work:/usr/sbin/nologin' >> /etc/passwd \
 && echo 'sandbox:x:10001:' >> /etc/group

COPY entrypoint.py /opt/vtest/entrypoint.py
RUN chmod -R a+rX,go-w /opt/vtest

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/work

USER 10001:10001
WORKDIR /work
ENTRYPOINT ["python3", "-I", "/opt/vtest/entrypoint.py"]
