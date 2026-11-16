# AI Cyber Shield local harness: Kali Linux + OpenCode server + security tools.
FROM kalilinux/kali-rolling

ARG OPENCODE_VERSION=1.14.33
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    SHIELD_HOME=/workspace

# Security tools (all from the Kali repositories) + runtime for OpenCode and the gateway.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git jq unzip dnsutils whois iputils-ping netcat-traditional libcap2-bin \
      nodejs npm \
      python3 python3-fastapi python3-uvicorn python3-httpx \
      nmap nikto sqlmap whatweb gobuster ffuf dirb sslscan testssl.sh \
      nuclei httpx-toolkit subfinder wafw00f arjun dalfox \
    && rm -rf /var/lib/apt/lists/*

# OpenCode (pinned) installed globally from npm.
RUN npm install -g "opencode-ai@${OPENCODE_VERSION}" && npm cache clean --force && opencode --version

# Let nmap do SYN/OS scans without running the whole container as root.
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(readlink -f /usr/lib/nmap/nmap || readlink -f "$(command -v nmap)")"

RUN useradd --create-home --shell /bin/bash shield

COPY --chown=shield:shield workspace/ /workspace/
COPY --chown=shield:shield gateway/ /opt/shield/gateway/
COPY --chown=shield:shield entrypoint.sh /opt/shield/entrypoint.sh

# Scope guard: a shadow bin dir (first on PATH) of symlinks to the guard, one per network tool.
RUN install -m 0755 /workspace/bin/scope-guard /opt/shield/scope-guard \
    && mkdir -p /opt/shield/guardbin \
    && for t in nmap masscan nikto sqlmap whatweb gobuster ffuf dirb sslscan testssl.sh \
                nuclei httpx subfinder wafw00f arjun dalfox curl wget; do \
         ln -sf /opt/shield/scope-guard /opt/shield/guardbin/$t; \
       done \
    && chmod +x /opt/shield/entrypoint.sh \
    && mkdir -p /workspace/data/captures /workspace/data/reports /workspace/data/scans \
                /home/shield/.local/share/opencode \
    && chown -R shield:shield /workspace /home/shield

ENV SHIELD_GUARD_DIR=/opt/shield/guardbin
ENV PATH=/opt/shield/guardbin:$PATH
# Also prepend the guard dir for login shells (e.g. a terminal opened in the OpenCode UI).
RUN printf 'export PATH=/opt/shield/guardbin:$PATH\n' > /etc/profile.d/00-shield-guard.sh

USER shield
WORKDIR /workspace

# Pre-fetch nuclei templates so the first scan doesn't stall (best effort).
RUN nuclei -update-templates -silent || true

# 7878 = gateway API for the browser extension, 4096 = OpenCode server (web UI + API).
EXPOSE 7878 4096
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s \
  CMD curl -fsS http://127.0.0.1:7878/api/health >/dev/null || exit 1

ENTRYPOINT ["/opt/shield/entrypoint.sh"]
