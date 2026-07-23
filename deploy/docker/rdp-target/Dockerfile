# RDP test target for the pamv1 in-portal RDP viewer demo: a throwaway Linux
# desktop (XFCE) served over xrdp, so the rendered-pixels path can be verified
# end to end without a Windows host.
#
# NOT hardened — it runs xrdp as root with a weak, well-known password. For local
# end-to-end testing only; never deploy it.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      xrdp xorgxrdp xfce4 xfce4-terminal dbus-x11 dbus iproute2 \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# Demo login — MUST match the credential the compose file seeds into pamv1.
ARG RDP_USER=demo
ARG RDP_PASS=Demo-RDP-Pass1!
RUN useradd -m -s /bin/bash "$RDP_USER" && echo "$RDP_USER:$RDP_PASS" | chpasswd

# Every RDP session launches XFCE.
RUN printf '#!/bin/sh\nexec startxfce4\n' > /etc/xrdp/startwm.sh && chmod +x /etc/xrdp/startwm.sh

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 3389
HEALTHCHECK --interval=10s --timeout=3s --start-period=25s --retries=6 \
  CMD ss -lnt 2>/dev/null | grep -q ':3389' || exit 1
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
