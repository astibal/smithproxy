#!/usr/bin/env bash
ORIG_DIR="$(pwd)"

# === LOAD DEFAULTS ====
SUFFIX_LONG=""
SUFFIX_SHORT=""


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

if [ "${CURL_UPLOAD_OPTS}" == "" ]; then
  CURL_UPLOAD_OPTS="--ftp-ssl-control"
fi

DEBIAN_DIR="debian-0.9"

if [ "${MAKE_DEBUG}" == "Y" ]; then
  SUFFIX_LONG="-debug"
  SUFFIX_SHORT="-dbg"
  DEBIAN_DIR="debian-0.9${SUFFIX_LONG}"
fi


CUR_DIR=/tmp/smithproxy_build
mkdir ${CUR_DIR}
cp ./*.sh ${CUR_DIR}
cp -r ${DEBIAN_DIR} ${CUR_DIR}/debian


CUSTOM_DEBIAN_DIR="${DEBIAN_DIR}_$(./distro.sh)"
if [[ -d "${CUSTOM_DEBIAN_DIR}" ]]; then
    echo "custom debian directory found, copying files"
    cp -rv "${CUSTOM_DEBIAN_DIR}"/* ${CUR_DIR}/debian/
fi


cd "${CUR_DIR}" || exit 255
##
## trap Ctrl-C, don't continue with script if hit in longer task (ie. make)
##
trap ctrl_c INT
function ctrl_c() {
        echo "Ctrl-C: exiting working directory ${CUR_DIR}"
        cd "${ORIG_DIR}" || exit 255
        exit 255
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

    O="$(pwd)"
    cd "${CUR_DIR}" || exit 255

    cleanup

    git clone --recursive https://github.com/astibal/smithproxy.git smithproxy -b "${SMITHPROXY_BRANCH}"

    cd "${O}" || exit 255
}
# upload file function
upload() {
    FILE=$1
    URL=$2

    if [[ -f ${FILE} ]]; then
        echo "source ${FILE} exists"
        curl ${CURL_UPLOAD_OPTS} --ftp-create-dirs -T "${FILE}" "$URL"
    else
        echo "source ${FILE} doesn't exist!"
    fi
}

# upload file if it URL doesn't exist
safe_upload() {
    FILE=$1
    URL=$2

    if curl --output /dev/null --silent --head --fail "${URL}"; then
      echo "target URL exists: ${URL}, aborting"
    else
      echo "target URL does not exist: ${URL}, uploading"
      upload "${FILE}" "${URL}"
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

cd smithproxy || exit 255

GIT_DESCR=$(git describe --tags)

echo "Git describe: ${GIT_DESCR}"

GIT_TAG=$(echo "${GIT_DESCR}" | awk -F'-' '{ print $1 }')
GIT_PATCH_DIST=$(echo "${GIT_DESCR}" | awk -F'-' '{ print $2 }')
GIT_PATCH=$(echo "${GIT_DESCR}" | awk -F'-' '{ print $3 }')

if [ "${GIT_PATCH_DIST}" == "" ]; then
    echo "Git patch unknown, must abort"
    exit 255
elif [ "${GIT_PATCH_DIST}" == "0" ]; then
    echo "Git at zero patch - setting to p0"
    GIT_PATCH_DIST="p0"
    exit 255
fi
cd ..

mv smithproxy smithproxy-"${GIT_TAG}"
ln -s smithproxy-"${GIT_TAG}" smithproxy_src

# create tarball for build
tar cfz smithproxy_"${GIT_TAG}".orig.tar.gz --exclude-vcs smithproxy-"${GIT_TAG}"

# make source tarball
rm /tmp/smithproxy-src.tar.gz ; cp smithproxy_"${GIT_TAG}".orig.tar.gz /tmp/smithproxy-src.tar.gz

cd smithproxy_src || exit 255


# initialize debian versioning
DEB_CUR="${GIT_PATCH_DIST}"
VER="${GIT_TAG}"
ARCH="$(dpkg --print-architecture)"

echo "Git last version: ${GIT_TAG}, ${GIT_PATCH_DIST} commits ahead. Debian patchlevel set to ${DEB_CUR}"
cd "${CUR_DIR}" || exit 255


# get major version and guess linux distro
VER_MAJ=$(echo "$VER" | awk -F. '{ print $1"."$2; }')
DEB_DIR="smithproxy-$VER"

DISTRO=$(./distro.sh)

echo "Distro detected: ${DISTRO}"
echo "Major version: $VER_MAJ, debian directory set to $DEB_DIR"


# try to get passwords from an argument for case script is run interactive
if [ "${FTP_UPLOAD_PWD}" == "" ]; then
    FTP_UPLOAD_PWD=$1
fi
# if password is still unknown, ask for it
if [ "${FTP_UPLOAD_PWD}" == "" ]; then
    read -r -s -p "Enter ftp upload password: " FTP_UPLOAD_PWD
fi

#echo "DEBUG: using password $FTP_UPLOAD_PWD"

UPLOAD_URL="ftp://${FTP_UPLOAD_USER}:${FTP_UPLOAD_PWD}@${FTP_UPLOAD_PATH}"

UPLOAD_STREAMLINE_CHANGELOG="N"

DEBEMAIL="support@smithproxy.org"
DEBFULLNAME="Smithproxy Support"


echo "Preparing version ${VER}-${DEB_CUR}"
cp -rv debian "${DEB_DIR}"

echo "Filling changelog based on git log ..."

./gen_changelog.sh smithproxy_src/ > "${DEB_DIR}/debian/changelog"

echo "cd to ${DEB_DIR}"
cd "${DEB_DIR}" || exit 255


echo "Creating debian packages..."
debuild -us -uc -j"$(nproc)"

echo "cd to ${CUR_DIR}"
cd "${CUR_DIR}" || exit 255

#FIXME: archive contains cmake temp files - archive is too big.
#echo "Archiving"
#mkdir archives
#tar cvfz archives/smithproxy_${VER}-${DEB_CUR}_${DISTRO}_build.tar.gz --exclude-vcs -- smithproxy_${VER}/ smithproxy-${VER}/ socle/

echo "Saving changelog"
cp -f "smithproxy-${VER}/debian/changelog" debian/

if [ "${UPLOAD_STREAMLINE_CHANGELOG}" == "Y" ]; then
    URL="${UPLOAD_URL}/${VER_MAJ}/changelog"
    FILE="smithproxy-${VER}/debian/changelog"

    if [ "${FTP_UPLOAD_PWD}" == "" ]; then
        echo "password was not provided - no uploads"
    else
        echo "..uploading also streamline changelog, because this is its first build"
        safe_upload "${FILE}" "${URL}"
    fi
fi


##
## Final upload of produced files - only new files will be uploaded, and only if password has been provided
##

if [ "$FTP_UPLOAD_PWD" == "" ]; then
    echo "password was not provided - no uploads"
else

    echo "File(s) being uploaded now."
    DEB_FILE=smithproxy${SUFFIX_SHORT}_${VER}-${DEB_CUR}_${ARCH}.deb

    if [ "${GIT_PATCH_DIST}" != "0" ]; then
        DEB_PATH="${UPLOAD_URL}/${VER_MAJ}/${DISTRO}/snapshots/binary-${ARCH}"
    else
        DEB_PATH="${UPLOAD_URL}/${VER_MAJ}/${DISTRO}/release/binary-${ARCH}"
    fi

    DEB_URL="${DEB_PATH}/$DEB_FILE"


    # upload the actual package
    safe_upload "${DEB_FILE}" "${DEB_URL}"

    # upload package sha256 sum
    sha256sum "${DEB_FILE}" > "${DEB_FILE}.sha256"
    safe_upload "${DEB_FILE}.sha256" "${DEB_URL}.sha256"

    if [ "${MAKE_DEBUG}" == "Y" ]; then
        echo "debug release, skipping complementary files"
    else
        # overwrite files if thy exist
        safe_upload "smithproxy-${VER}/debian/changelog" "${DEB_PATH}/smithproxy_${VER}-${DEB_CUR}.changelog"
        #upload README ${DEB_PATH}/README

        # upload Release_Notes from src root
        upload /tmp/smithproxy_build/smithproxy_src/Release_Notes.md "${UPLOAD_URL}/${VER_MAJ}/Release_Notes.md"
    fi

    #### LATEST build overwrite - only for snapshots
    if [ "${GIT_PATCH_DIST}" != "0" ]; then

        DEB_FILE_LATEST=smithproxy${SUFFIX_SHORT}_${VER_MAJ}-latest_${ARCH}.deb
        DEB_URL_LATEST="${DEB_PATH}/$DEB_FILE_LATEST"

        # upload latest (always overwrite, rename it)
        upload "${DEB_FILE}" "${DEB_URL_LATEST}"

        # upload latest checksum
        sha256sum "${DEB_FILE}" > "${DEB_FILE_LATEST}.sha256"
        upload "${DEB_FILE_LATEST}.sha256" "${DEB_URL_LATEST}.sha256"


        if [ "${MAKE_DEBUG}" == "Y" ]; then
            echo "debug release, skipping complementary files"
        else
            upload "smithproxy-${VER}/debian/changelog" "${DEB_PATH}/smithproxy_${VER_MAJ}-latest.changelog"

            SRC_BALL="${UPLOAD_URL}src/smithproxy_src-${GIT_TAG}-${GIT_PATCH_DIST}.tar.gz"
            safe_upload /tmp/smithproxy-src.tar.gz "${SRC_BALL}"

            sha256sum /tmp/smithproxy-src.tar.gz > /tmp/smithproxy-src.tar.gz.sha256
            safe_upload /tmp/smithproxy-src.tar.gz.sha256 "${SRC_BALL}.sha256"

            rm /tmp/smithproxy-src.tar.gz
            rm /tmp/smithproxy-src.tar.gz.sha256
        fi
    fi
    echo "Finished."
fi


echo "Finished: exiting working directory $CUR_DIR (please clean it up)"
cd "${ORIG_DIR}" || exit 255