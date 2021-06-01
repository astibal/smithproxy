#
#
# meant to be run like this:
#
# export SRC="$HOME/pro/smithproxy"
# export DST="`mktemp -d --suffix smithproxy`"
# cp -r $SRC $DST && cd $DST
# rm -rf smithproxy/cmake-build* ; rm -rf smithproxy/build ; rm -rf smithproxy/venv ; rm smithproxy/*.snap
# sudo docker build . -f smithproxy/tools/docker/0.9/run/ubuntu18.04-0.9-debug-localsrc.dockerfile --tag build.ubuntu18.dbg-local

FROM ubuntu:20.04

LABEL org.smithproxy.docker.image="astibal/smithproxy:ubuntu20.04-0.9-run-release-localsrc"

RUN mkdir app/

WORKDIR /app

RUN apt update && apt -y install git && DEBIAN_FRONTEND=noninteractive apt-get install -y tzdata && apt -y install gdb 


RUN rm -rf /smithproxy

# copy source
COPY smithproxy/ /smithproxy/

# copy docker root extras
COPY smithproxy/tools/docker/guest-scripts/* /app/

RUN cd /smithproxy && ./tools/linux-deps.sh && \
mkdir build ; cd build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j `nproc` install

# Define environment variable

# Run smithproxy when the container launches
CMD echo "Starting smithproxy (Release) .... " && ( /etc/init.d/smithproxy start ) > /dev/null 2>&1 && sleep 2 && \
    echo "SSL MITM CA cert:" && cat /etc/smithproxy/certs/default/ca-cert.pem && echo ; echo "run sx_cli" && bash
