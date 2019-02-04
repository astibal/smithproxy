#!/usr/bin/env bash

DEB_MIN=`cat DEB_VERSION`
DEB_CUR=`expr  $DEB_MIN + 1`
VER=`cat VERSION`
VER_MAJ=`cat VERSION | awk -F. '{ print $1"."$2; }'`
DEB_DIR="smithproxy-$VER"
CUR_DIR=`pwd`
DISTRO=`./distro.sh`

PYLIBCONFIG2_FILE="python-pylibconfig2_0.2.5-1_all.deb"
UPLOAD_PWD=$1

if [ "${UPLOAD_PWD}" == "" ]; then
    read -s -p "Enter upload password: " UPLOAD_PWD
fi

UPLOAD_URL="ftp://mag0net_uploader:${UPLOAD_PWD}@ftp.mag0.net/web/out/smithproxy"


# upload file function
upload() {
    FILE=$1
    URL=$2

    curl -tlsv1.2 --ftp-ssl-control --ftp-create-dirs -T $FILE -k $URL
}
# upload file if it URL doesn't exist
safe_upload() {
    FILE=$1
    URL=$2

    if curl --output /dev/null --silent --head --fail "$URL"; then
      echo "URL exists: $URL, aborting"
    else
      echo "URL does not exist: $URL, uploading"
      upload $FILE $URL
    fi
}

echo "Downloading pylibconfig2 package"
wget https://bitbucket.org/astibal/smithproxy/downloads/${PYLIBCONFIG2_FILE} -O ${PYLIBCONFIG2_FILE}

echo "File(s) being uploaded now."
DEB_FILE=smithproxy_${VER}-${DEB_CUR}*.deb
DEB_URL=${UPLOAD_URL}/${VER_MAJ}/${DISTRO}/$DEB_FILE

safe_upload $DEB_FILE $DEB_URL
safe_upload ${PYLIBCONFIG2_FILE} ${UPLOAD_URL}/${VER_MAJ}/${DISTRO}/${PYLIBCONFIG2_FILE}

# overwrite files if thy exist
upload smithproxy-${VER}/debian/changelog ${UPLOAD_URL}/${VER_MAJ}/${DISTRO}/changelog
upload README ${UPLOAD_URL}/${VER_MAJ}/${DISTRO}/README

echo "Finished."

