#
FROM debian:10

LABEL org.smithproxy.docker.image="astibal/smithproxy:debian10-0.9-run"

WORKDIR /app

RUN apt update && apt -y install git && DEBIAN_FRONTEND=noninteractive apt-get install -y tzdata

RUN git clone --recursive https://github.com/astibal/smithproxy.git -b master smithproxy

RUN cd smithproxy && ./tools/linux-deps.sh && ./tools/linux-build.sh

# Define environment variable

# Run smithproxy when the container launches
CMD echo "Starting smithproxy .... " && ( /etc/init.d/smithproxy start ) > /dev/null 2>&1 && sleep 3 && \
    echo "SSL MITM CA cert" && cat /etc/smithproxy/certs/default/ca-cert.pem && sx_cli && bash