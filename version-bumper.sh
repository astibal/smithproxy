#!/bin/sh

# do  this, as git hooks don't work well in my IDE

sed -i "s/^version: [^ ]\+/version: `git describe --tags`/" /home/astib/pro/smithproxy/snapcraft.yaml
