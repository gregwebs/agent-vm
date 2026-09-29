# PROTOTYPE: a tool layer whose build fails, to check that its failure does not
# cancel (and so un-cache) the other tools' builds.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
RUN echo "broken tool: failing on purpose" >&2 && exit 1
