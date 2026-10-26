# Deliberately unsuitable runtime image: keep base, app env, cache, apt, and shell.
# No dependency lock or separate runtime stage is used. Do not deploy this example.
FROM continuumio/miniconda3:26.7.1

# Build tooling is intentionally shipped rather than isolated in a builder stage.
RUN apt-get update && apt-get install -y --no-install-recommends make \
    && rm -rf /var/lib/apt/lists/*

# Force copies to keep the demo independent of cache link accounting.
# Keep package archives and extracted cache entries to demonstrate IMG001/IMG002.
RUN conda create --yes --copy --name app python=3.13 requests

# Duplicate one real downloaded archive, then delete it in a later layer.
# Its bytes remain in image history, demonstrating IMG004 without fake metadata.
RUN set -eu; \
    package="$(find /opt/conda/pkgs -maxdepth 1 -type f -name '*.conda' -print -quit)"; \
    test -n "$package"; \
    cp "$package" /opt/conda/pkgs/demo-retained-1.0-0.conda
RUN rm /opt/conda/pkgs/demo-retained-1.0-0.conda

WORKDIR /app
COPY app.py /app/app.py

ENV PATH="/opt/conda/envs/app/bin:${PATH}"
# Shell and conda tooling are deliberately used at startup to preserve that caveat.
CMD ["/bin/bash", "-c", "conda run --no-capture-output -n app python /app/app.py"]
