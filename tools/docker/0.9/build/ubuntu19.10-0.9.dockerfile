#
FROM astibal/smithproxy:ubuntu19.10-0.9-base
LABEL org.smithproxy.docker.image="astibal/smithproxy:ubuntu19.10-0.9-build"


# Set the working directory to /app
WORKDIR /app


RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tzdata && apt -y install git-buildpackage

# 0.9 is currently master
RUN \
    git clone https://github.com/astibal/smithproxy.git smithproxy && cd smithproxy

CMD cd /app/smithproxy/tools/build-scripts/deb && cat README.txt && echo && /bin/bash