#
FROM astibal/smithproxy:ubuntu18.04-0.9-base

LABEL org.smithproxy.docker.image="astibal/smithproxy:ubuntu18.04-0.9-run-debug-localsrc"

# Set the working directory to /app
WORKDIR /app

RUN apt -y install gdb valgrind


RUN rm -rf /smithproxy

COPY smithproxy/ /smithproxy/
COPY *.sh /app


RUN cd /smithproxy && \
mkdir build ; cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug && make -j `nproc` install

# Define environment variable

# Run smithproxy when the container launches
CMD echo "Starting smithproxy .... " && ( /etc/init.d/smithproxy start ) > /dev/null 2>&1 && sleep 3 && \
    echo "SSL MITM CA cert (add to trusted CAs):" && cat /etc/smithproxy/certs/default/ca-cert.pem && echo ; echo "run smithproxy_cli" && bash
