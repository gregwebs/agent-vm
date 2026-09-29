# PROTOTYPE project tooling layer, chained on top of the stitched composed
# tool image exactly as `--layer DIR` does today.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
RUN printf '#!/bin/sh\necho project-layer on top of the stitched image\n' > /usr/local/bin/project-hello \
 && chmod 0755 /usr/local/bin/project-hello
