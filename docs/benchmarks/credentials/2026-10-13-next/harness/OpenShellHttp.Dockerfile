# Verify the base image ID recorded in image-build.json before building.
FROM bench-openshell-agents:latest
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
# The existing ordinary Ubuntu user owns /work. OpenShell resolves this identity
# before launch and preserves its default outer fences and runtime images.
USER ubuntu:ubuntu
WORKDIR /work
