#!/usr/bin/env bash
ORIG_DIR=`pwd`

# === LOAD DEFAULTS ====


if [ "${FTP_UPLOAD_USER}" == "" ]; then
    FTP_UPLOAD_USER="mag0net_uploader"
fi

if [ "${FTP_UPLOAD_PATH}" == "" ]; then
    FTP_UPLOAD_PATH="ftp.mag0.net/web/out/smithproxy"
fi

if [ "${HTTP_CHECK_PATH}" == "" ]; then
    HTTP_CHECK_PATH="www.mag0.net/out/smithproxy"
fi

if [ "${SO_BRANCH}" == "" ]; then
    SO_BRANCH="master"
fi

if [ "${SX_BRANCH}" == "" ]; then
    SX_BRANCH="master"
fi

DEBIAN_DIR="debian-0.9-debug"


CUR_DIR=/tmp/smithproxy_build
mkdir ${CUR_DIR}
cp *.sh ${CUR_DIR}
cp -rv ${DEBIAN_DIR} ${CUR_DIR}/debian
cd ${CUR_DIR}
##
## trap Ctrl-C, don't continue with script if hit in longer task (ie. make)
##
trap ctrl_c INT
function ctrl_c() {
        echo "Ctrl-C: exiting working directory $CUR_DIR"
        cd $ORIG_DIR
        exit -1
}


# cleanup directory
function cleanup () {
    (
    rm ${CUR_DIR}/smithoproxy_*.orig.tar.gz
    rm -rf ${CUR_DIR}/smithproxy_*
    rm -rf ${CUR_DIR}/smithproxy-*
    rm -rf ${CUR_DIR}/socle*
    ) > /dev/null 2>&1

}

# download source from git
# @param1 - socle branch
# @param2 - smithproxy branch
function sync() {
    SOCLE_BRANCH=$1
    SMITHPROXY_BRANCH=$2

    O=`pwd`
    cd $CUR_DIR

    cleanup

    git clone --recursive http://github.com/astibal/smithproxy.git smithproxy -b ${SMITHPROXY_BRANCH}

    cd $O
}
# upload file function
upload() {
    FILE=$1
    URL=$2

    if [[ -f $FILE ]]; then
        echo "$FILE exists"
        curl -tlsv1.2 --cipher 'DEFAULT:!DH' --ftp-ssl-control --ftp-create-dirs -T $FILE -k $URL
    else
        echo "$FILE doesn't exist!"
    fi
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


##
## get source !!
##

sync $SO_BRANCH $SX_BRANCH

##
## get proper versions from GIT. We set debian patch-level to distance from
## latest --tag.
##

cd smithproxy

GIT_DESCR=`git describe --tags`
GIT_TAG=`echo ${GIT_DESCR} | awk -F'-' '{ print $1 }'`
GIT_PATCH_DIST=`echo ${GIT_DESCR} | awk -F'-' '{ print $2 }'`
GIT_PATCH=`echo ${GIT_DESCR} | awk -F'-' '{ print $3 }'`

if [ "${GIT_PATCH_DIST}" == "" ]; then
    GIT_PATCH_DIST="0"
fi
cd ..

mv smithproxy smithproxy-${GIT_TAG}
ln -s smithproxy-${GIT_TAG} smithproxy_src

# create tarball for build
tar cfz smithproxy_${GIT_TAG}.orig.tar.gz --exclude-vcs smithproxy-${GIT_TAG}

cd smithproxy_src


# initialize debian versioning
DEB_CUR=$GIT_PATCH_DIST
VER=$GIT_TAG
ARCH=`dpkg --print-architecture`

echo "Git last version: $GIT_TAG, $GIT_PATCH_DIST commits ahead. Debian patchlevel set to $DEB_CUR"
cd $CUR_DIR


# get major version and guess linux distro
VER_MAJ=`echo $VER | awk -F. '{ print $1"."$2; }'`
DEB_DIR="smithproxy-$VER"
DISTRO=`./distro.sh`

echo "Major version: $VER_MAJ, debian directory set to $DEB_DIR"


# try to get passwords from an argument for case script is run interative
if [ "${FTP_UPLOAD_PWD}" == "" ]; then
    FTP_UPLOAD_PWD=$1
fi
# if password is still unknown, ask for it
if [ "${FTP_UPLOAD_PWD}" == "" ]; then
    read -s -p "Enter ftp upload password: " FTP_UPLOAD_PWD
fi

#echo "DEBUG: using password $FTP_UPLOAD_PWD"

UPLOAD_URL="ftp://${FTP_UPLOAD_USER}:${FTP_UPLOAD_PWD}@${FTP_UPLOAD_PATH}"
DOWNLOAD_URL="http://${HTTP_CHECK_PATH}"

UPLOAD_STREAMLINE_CHANGELOG="N"

DEBEMAIL="support@smithproxy.org"
DEBFULLNAME="Smithproxy Support"


echo "Preparing version ${VER}-${DEB_CUR}"
cp -rv debian $DEB_DIR

echo "Filling changelog based on git log ..."

./gen_changelog.sh smithproxy_src/ > $DEB_DIR/debian/changelog

echo "cd to $DEB_DIR"
cd $DEB_DIR


echo "Creating debian packages..."
debuild -us -uc -j`nproc`

echo "cd to $CUR_DIR"
cd $CUR_DIR

#FIXME: archive contains cmake temp files - archive is too big.
#echo "Archiving"
#mkdir archives
#tar cvfz archives/smithproxy_${VER}-${DEB_CUR}_${DISTRO}_build.tar.gz --exclude-vcs -- smithproxy_${VER}/ smithproxy-${VER}/ socle/

echo "Saving changelog"
cp -f smithproxy-${VER}/debian/changelog debian/

if [ "$UPLOAD_STREAMLINE_CHANGELOG" == "Y" ]; then
    URL="${UPLOAD_URL}/${VER_MAJ}/changelog"
    FILE=smithproxy-${VER}/debian/changelog

    if [ "$FTP_UPLOAD_PWD" == "" ]; then
        echo "password was not provided - no uploads"
    else
        echo "..uploading also streamline changelog, because this is its first build"
        safe_upload $FILE $URL
    fi
fi


##
## Final upload of produced files - only new files will be uploaded, and only if password has been provided
##

if [ "$FTP_UPLOAD_PWD" == "" ]; then
    echo "password was not provided - no uploads"
else

    echo "File(s) being uploaded now."
    DEB_FILE=smithproxy-dbg_${VER}-${DEB_CUR}_${ARCH}.deb

    if [ "${GIT_PATCH_DIST}" != "0" ]; then
        DEB_PATH="${UPLOAD_URL}/${VER_MAJ}/${DISTRO}/snapshots"
    else
        DEB_PATH="${UPLOAD_URL}/${VER_MAJ}/${DISTRO}/release"
    fi

    DEB_URL="${DEB_PATH}/$DEB_FILE"


    # upload the actual package
    safe_upload $DEB_FILE $DEB_URL

    # upload package sha256 sum
    sha256sum $DEB_FILE > $DEB_FILE.sha256
    safe_upload $DEB_FILE.sha256 $DEB_URL.sha256

    #### LATEST build overwrite - only for snapshots
    if [ "${GIT_PATCH_DIST}" != "0" ]; then

        DEB_FILE_LATEST=smithproxy-dbg_0.9-latest_${ARCH}.deb
        DEB_URL_LATEST="${DEB_PATH}/$DEB_FILE_LATEST"

        # upload latest (always overwrite, rename it)
        upload $DEB_FILE $DEB_URL_LATEST

        # upload latest checksum
        sha256sum $DEB_FILE > $DEB_FILE_LATEST.sha256
        upload $DEB_FILE_LATEST.sha256 $DEB_URL_LATEST.sha256

    fi

    echo "Finished."
fi


echo "Finished: exiting working directory $CUR_DIR (please clean it up)"
cd $ORIG_DIR