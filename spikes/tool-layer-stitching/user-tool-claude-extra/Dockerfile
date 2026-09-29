# PROTOTYPE user `layer = { path = … }` tool with a declared parent (claude).
# It needs `claude` at build time, which a stage built FROM the bare base
# would not have.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ENV PATH=/opt/tool-claude-extra/bin:${PATH}
RUN mkdir -p /opt/tool-claude-extra/bin \
 && claude --version > /opt/tool-claude-extra/claude-version \
 && printf '#!/bin/sh\necho "claude-extra built against: $(cat /opt/tool-claude-extra/claude-version)"\n' \
      > /opt/tool-claude-extra/bin/claude-extra \
 && chmod -R a+rX /opt/tool-claude-extra && chmod +x /opt/tool-claude-extra/bin/claude-extra
