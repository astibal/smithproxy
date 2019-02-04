#!/usr/bin/env bash
CUR_DIR=`pwd`


##
## trap Ctrl-C, don't continue with script if hit in longer task (ie. make)
##
trap ctrl_c INT
function ctrl_c() {
        echo "Ctrl-C: bailing out."
        cd $CUR_DIR
        exit -1
}

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


##
## get proper versions from GIT. We set debian patch-level to distance from
## latest --tag.
##
cd smithproxy_src

GIT_DESCR=`git describe --tags`
GIT_TAG=`echo ${GIT_DESCR} | awk -F'-' '{ print $1 }'`
GIT_PATCH_DIST=`echo ${GIT_DESCR} | awk -F'-' '{ print $2 }'`
GIT_PATCH=`echo ${GIT_DESCR} | awk -F'-' '{ print $3 }'`

if [ "${GIT_PATCH_DIST}" == "" ]; then
    GIT_PATCH_DIST="0"
fi

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




UPLOAD_PWD=$1
if [ "${UPLOAD_PWD}" == "" ]; then
    read -s -p "Enter upload password: " UPLOAD_PWD
fi

#echo "DEBUG: using password $UPLOAD_PWD"

UPLOAD_URL="ftp://mag0net_uploader:${UPLOAD_PWD}@ftp.mag0.net/web/out/smithproxy"
DOWNLOAD_URL="http://www.mag0.net/out/smithproxy"

UPLOAD_STREAMLINE_CHANGELOG="N"

DEBEMAIL="support@smithproxy.org"
DEBFULLNAME="Smithproxy Support"


echo "Preparing version ${VER}-${DEB_CUR}"
cp -rv debian $DEB_DIR

echo "cd to $DEB_DIR"
cd $DEB_DIR

echo "Filling changelog..."
export DEBEMAIL="$DEBEMAIL"
export DEBFULLNAME="$DEBFULLNAME"

echo "Attempting to download ${DOWNLOAD_URL}/${VER_MAJ}/${DISTRO}/changelog"
wget ${DOWNLOAD_URL}/${VER_MAJ}/${DISTRO}/changelog -O debian/changelog.dnld
#wget ${DOWNLOAD_URL}/${DISTRO}/changelog -O debian/changelog

if [ ! -s debian/changelog.dnld ]; then

    echo "Attempting to download STREAMLINE ${DOWNLOAD_URL}/${VER_MAJ}/changelog"
    wget ${DOWNLOAD_URL}/${VER_MAJ}/changelog -O debian/changelog.dnld
    
    if [ ! -s debian/changelog.dnld ]; then 

        echo "even streamline changelog doesn't exist on server, creating a new one"
        echo "smithproxy (${VER}-1) unstable; urgency=medium"   > debian/changelog
        echo ""                                                 >> debian/changelog
        echo "    * initial build for this version"    >> debian/changelog
        echo ""                                                 >> debian/changelog
        echo "    -- Smithproxy Support <support@smithproxy.org>  `date -R`" >> debian/changelog
        echo ""                                                 >> debian/changelog
        
        UPLOAD_STREAMLINE_CHANGELOG="Y"
    else
        echo "streamline changelog exists"
        cp -f debian/changelog.dnld debian/changelog
    fi
    
else
    echo "using downloaded changelog"
    cp debian/changelog.dnld debian/changelog
fi


echo "dch -v ${VER}-${DEB_CUR} --package smithproxy"
dch -v ${VER}-${DEB_CUR} --package smithproxy


echo "Creating debian packages..."
debuild -us -uc

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

    if [ "$UPLOAD_PWD" == "" ]; then
        echo "password was not provided - no uploads"
    else
        echo "..uploading also streamline changelog, because this is its first build"
        safe_upload $FILE $URL
    fi
fi


##
## Final upload of produced files - only new files will be uploaded, and only if password has been provided
##

if [ "$UPLOAD_PWD" == "" ]; then
    echo "password was not provided - no uploads"
else

    PYLIBCONFIG2_FILE="python-pylibconfig2_0.2.5-1_all.deb"

    echo "Downloading pylibconfig2 package"
    wget https://bitbucket.org/astibal/smithproxy/downloads/${PYLIBCONFIG2_FILE} -O ${PYLIBCONFIG2_FILE}

    echo "File(s) being uploaded now."
    DEB_FILE=smithproxy_${VER}-${DEB_CUR}_${ARCH}.deb
    DEB_URL=${UPLOAD_URL}/${VER_MAJ}/${DISTRO}/$DEB_FILE

    safe_upload $DEB_FILE $DEB_URL
    safe_upload ${PYLIBCONFIG2_FILE} ${UPLOAD_URL}/${VER_MAJ}/${DISTRO}/${PYLIBCONFIG2_FILE}

    # overwrite files if thy exist
    upload smithproxy-${VER}/debian/changelog ${UPLOAD_URL}/${VER_MAJ}/${DISTRO}/changelog
    upload README ${UPLOAD_URL}/${VER_MAJ}/${DISTRO}/README

    echo "Finished."
fi
