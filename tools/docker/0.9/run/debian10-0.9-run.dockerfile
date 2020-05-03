#
FROM astibal/smithproxy:debian10-0.9-base

LABEL org.smithproxy.docker.image="astibal/smithproxy:debian10-0.9-run"

# Set the working directory to /app
WORKDIR /app

RUN cd smithproxy && ./tools/linux-build.sh

# Define environment variable

# Run smithproxy when the container launches
CMD echo "Starting smithproxy .... " && ( /etc/init.d/smithproxy start ) > /dev/null 2>&1 && sleep 3 && \
    echo "SSL MITM CA cert (add to trusted CA's):" && cat /etc/smithproxy/certs/default/ca-cert.pem && smithproxy_cli && bash