FROM ghcr.io/void-linux/void-glibc:latest

RUN xbps-install -Syu -y shadow && \
    rm -rf /var/cache/xbps \
    && useradd -m -d /home/challenger -s /bin/false challenger && \
    chown -R root:root /home/challenger && \
    chmod -R 555 /home/challenger

COPY out/ynetd /home/challenger/ynetd
COPY out/prequels_revenge /home/challenger/prequels_revenge
COPY assets/messages.db /home/challenger/

RUN chmod 555 /tmp && \
    chmod 555 /var/tmp && \
    chmod 555 /dev && \
    chmod 555 /run

USER challenger
WORKDIR /home/challenger

CMD ["/bin/sh", "-c", "/home/challenger/ynetd -p ${CHALLENGE_PORT} /home/challenger/prequels_revenge -se y"]
