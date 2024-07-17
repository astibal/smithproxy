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

if [ "${SX_BRANCH}" == "" ]; then
    SX_BRANCH="$1"
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
cp ../../gen_changelog.py ${CUR_DIR}
cp -r ${DEBIAN_DIR} ${CUR_DIR}/debian


CUSTOM_DEBIAN_DIR="${DEBIAN_DIR}_$(./distro.sh)"
if [[ -d "${CUSTOM_DEBIAN_DIR}" ]]; then
    echo "createdeb: custom debian directory found, copying files"
    cp -rv "${CUSTOM_DEBIAN_DIR}"/* ${CUR_DIR}/debian/
fi


cd "${CUR_DIR}" || exit 255
##
## trap Ctrl-C, don't continue with script if hit in longer task (ie. make)
##
trap ctrl_c INT
function ctrl_c() {
        echo "createdeb: Ctrl-C: exiting working directory ${CUR_DIR}"
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
    SMITHPROXY_BRANCH=$1

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
        echo "createdeb: source ${FILE} exists"
        curl ${CURL_UPLOAD_OPTS} --ftp-create-dirs -T "${FILE}" "$URL"
    else
        echo "createdeb: source ${FILE} doesn't exist!"
    fi
}

# upload file if it URL doesn't exist
safe_upload() {
    FILE=$1
    URL=$2

    if curl --output /dev/null --silent --head --fail "${URL}"; then
      echo "createdeb: target URL exists: ${URL}, aborting"
    else
      echo "createdeb: target URL does not exist: ${URL}, uploading"
      upload "${FILE}" "${URL}"
    fi
}


##
## get source !!
##

sync "${SX_BRANCH}"

##
## get proper versions from GIT. We set debian patch-level to distance from
## latest --tag.
##

cd smithproxy || exit 255

GIT_DESCR=$(git describe --tags)

if [[ "${GIT_DESCR}" =~ ^[^0-9] ]]; then
    echo "createdeb: trimming non-version prefix from the git tag"
    GIT_DESCR=$(echo "${GIT_DESCR}" | sed 's/[^0-9]*//')
fi


echo "createdeb: git describe: ${GIT_DESCR}"

GIT_TAG=$(echo "${GIT_DESCR}" | awk -F'-' '{ print $1 }')


GIT_PATCH_DIST=$(echo "${GIT_DESCR}" | awk -F'-' '{ print $2 }')
GIT_PATCH=$(echo "${GIT_DESCR}" | awk -F'-' '{ print $3 }')

if [ "${GIT_PATCH_DIST}" == "" ]; then
    echo "createdeb: git at zero empty - setting to p0"
    GIT_PATCH_DIST="p0"
elif [ "${GIT_PATCH_DIST}" == "0" ]; then
    echo "createdeb: git at zero patch - setting to p0"
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

echo "createdeb: git last version: ${GIT_TAG}, ${GIT_PATCH_DIST} commits ahead. Debian patchlevel set to ${DEB_CUR}"
cd "${CUR_DIR}" || exit 255


# get major version and guess linux distro
VER_MAJ=$(echo "$VER" | awk -F. '{ print $1"."$2; }')
DEB_DIR="smithproxy-$VER"

DISTRO=$(./distro.sh)

echo "createdeb: distro detected: ${DISTRO}"
echo "createdeb: major version: $VER_MAJ, debian directory set to $DEB_DIR"


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


DEBEMAIL="support@smithproxy.org"
DEBFULLNAME="Smithproxy Support"


echo "Preparing version ${VER}-${DEB_CUR}"
cp -rv debian "${DEB_DIR}"

echo "Filling changelog based on git log ..."

cd smithproxy_src
python3 ../gen_changelog.py --tag-prefix 0.9 --repo-url https://github.com/astibal --repo-name smithproxy
mv CHANGELOG.txt "/tmp/changelog.txt"
mv CHANGELOG.md  "/tmp/changelog.md"
cd ..

# keep debian changelog ugly as it's idiotically dogmatic format - I am giving up on this BS
./gen_debian_changelog.sh smithproxy_src > "${DEB_DIR}/debian/changelog"

echo "createdeb: cd to ${DEB_DIR}"
cd "${DEB_DIR}" || exit 255


echo "createdeb: creating debian packages..."
debuild -us -uc -j"$(nproc)"

echo "createdeb: cd to ${CUR_DIR}"
cd "${CUR_DIR}" || exit 255

#FIXME: archive contains cmake temp files - archive is too big.
#echo "Archiving"
#mkdir archives
#tar cvfz archives/smithproxy_${VER}-${DEB_CUR}_${DISTRO}_build.tar.gz --exclude-vcs -- smithproxy_${VER}/ smithproxy-${VER}/ socle/

echo "createdeb: saving changelog"
cp -f "smithproxy-${VER}/debian/changelog" debian/

##
## Final upload of produced files - only new files will be uploaded, and only if password has been provided
##

if [ "$FTP_UPLOAD_PWD" == "" ]; then
    echo "createdeb: password was not provided - no uploads"
else

    echo "createdeb: file(s) being uploaded now."
    DEB_FILE=smithproxy${SUFFIX_SHORT}_${VER}-${DEB_CUR}_${ARCH}.deb

    if [ ! -f "${DEB_FILE}" ]; then
      echo "createdeb: ${DEB_FILE} not found, exiting"
      exit 255
    fi

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
        echo "createdeb: debug release, skipping complementary files"
    else
        # overwrite files if thy exist
        safe_upload "smithproxy-${VER}/debian/changelog" "${DEB_PATH}/smithproxy_${VER}-${DEB_CUR}.changelog.debian.txt"
        safe_upload "/tmp/changelog.txt" "${DEB_PATH}/smithproxy_${VER}-${DEB_CUR}.changelog.txt"
        safe_upload "/tmp/changelog.md" "${DEB_PATH}/smithproxy_${VER}-${DEB_CUR}.changelog.md"
        #upload README ${DEB_PATH}/README

        # upload Release_Notes from src root
        upload /tmp/smithproxy_build/smithproxy_src/Release_Notes.md "${UPLOAD_URL}/${VER_MAJ}/Release_Notes.md"
    fi

    if [ "${GIT_PATCH_DIST}" != "0" ]; then

        if [ "${MAKE_DEBUG}" == "Y" ]; then
            echo "createdeb: debug release, skipping complementary files"
        else
            SRC_BALL="${UPLOAD_URL}src/smithproxy_src-${GIT_TAG}-${GIT_PATCH_DIST}.tar.gz"
            safe_upload /tmp/smithproxy-src.tar.gz "${SRC_BALL}"

            sha256sum /tmp/smithproxy-src.tar.gz > /tmp/smithproxy-src.tar.gz.sha256
            safe_upload /tmp/smithproxy-src.tar.gz.sha256 "${SRC_BALL}.sha256"

            rm /tmp/smithproxy-src.tar.gz
            rm /tmp/smithproxy-src.tar.gz.sha256
        fi
    fi
    echo "createdeb: finished."
fi


echo "createdeb: finished: exiting working directory $CUR_DIR (please clean it up)"
cd "${ORIG_DIR}" || exit 255