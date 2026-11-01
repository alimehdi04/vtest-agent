# vtest k6 sandbox image: localhost/vtest-k6:1
# Runs only vtest's fixed k6 template (vtest/sandbox/k6_template.js). Base image pinned by digest.
FROM docker.io/grafana/k6:2.3.0@sha256:7637f6a2c358cf1decd8b1f339649da429f5e91901ecee19bfc0486c9edb5b13

# No usage reporting to Grafana: the container has no network anyway, so don't even try.
ENV K6_NO_USAGE_REPORT=true \
    K6_NO_COLOR=true \
    HOME=/work

USER 12345:12345
WORKDIR /work
ENTRYPOINT ["k6"]
