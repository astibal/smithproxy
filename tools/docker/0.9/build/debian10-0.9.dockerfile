#
FROM astibal/smithproxy:debian10-0.9-base
LABEL org.smithproxy.docker.image="astibal/smithproxy:debian10-0.9-build"

# Set the working directory to /app
WORKDIR /app


RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tzdata && apt -y install git-buildpackage

# 0.9 is currently master
RUN \
    git clone https://github.com/astibal/smithproxy.git smithproxy && cd smithproxy

CMD cd /app/smithproxy/tools/pkg-scripts/deb && cat README.txt && echo && /bin/bash