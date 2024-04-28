FROM ghcr.io/void-linux/void-glibc:latest

RUN xbps-install -Syu -y shadow && \
    rm -rf /var/cache/xbps \
    && useradd -m -d /home/challenger -s /bin/false challenger && \
    chown -R root:root /home/challenger && \
    chmod -R 555 /home/challenger

COPY out/ynetd /home/challenger/ynetd
COPY out/prequel /home/challenger/prequel
COPY assets/messages.db /home/challenger/
COPY assets/messages_debug.db /home/challenger/

RUN chmod 555 /tmp && \
    chmod 555 /var/tmp && \
    chmod 555 /dev && \
    chmod 555 /run

USER challenger
WORKDIR /home/challenger

CMD ["/bin/sh", "-c", "/home/challenger/ynetd -p ${CHALLENGE_PORT} /home/challenger/prequel -se y"]
