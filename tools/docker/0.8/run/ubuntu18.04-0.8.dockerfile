#
FROM astibal/smithproxy:ubuntu18.04-0.8-base
LABEL org.smithproxy.docker.image="astibal/smithproxy:ubuntu18.04-0.8-run"

# Set the working directory to /app
WORKDIR /app


RUN git clone https://bitbucket.com/astibal/socle.git socle -b 0.8 && git clone https://bitbucket.com/astibal/smithproxy.git smithproxy -b 0.8 && \
cd smithproxy && mkdir build && cd build && cmake .. && make install

# Define environment variable

# Run smithproxy when the container launches
CMD echo "Starting smithproxy .... " && ( /etc/init.d/smithproxy start ) > /dev/null 2>&1 && sleep 10 && \
    echo "SSL MITM CA cert (add to trusted CA's):" && cat /etc/smithproxy/certs/default/ca-cert.pem && smithproxy_cli && bash