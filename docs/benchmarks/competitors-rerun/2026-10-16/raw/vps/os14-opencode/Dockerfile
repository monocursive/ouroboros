FROM bench-openshell:latest
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates ripgrep && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /opt/agents/bin /opt/bench /home/agent /work && chown 1000:1000 /home/agent /work
COPY bin/ /opt/agents/bin/
COPY harness/ /opt/bench/
RUN chmod -R a+rX /opt/agents /opt/bench
ENV HOME=/home/agent PATH=/opt/agents/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER 1000:1000
WORKDIR /work
CMD ["/bin/sleep", "infinity"]
