DEB_MIN=`cat DEB_VERSION`
DEB_CUR=`expr  $DEB_MIN + 1`
VER=`cat VERSION`
VER_MAJ=`cat VERSION | awk -F. '{ print $1"."$2; }'`
DEB_DIR="smithproxy-$VER"
CUR_DIR=`pwd`
DISTRO=`./distro.sh`
UPLOAD_URL="ftp://mag0net_uploader:Tr3asur3Ch3st@ftp.mag0.net/web/out/smithproxy"
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
wget ${DOWNLOAD_URL}/${DISTRO}/${VER_MAJ}/changelog -O debian/changelog.dnld
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
    cp -f debian/changelog.dnld debian/changelog
fi


dch -v ${VER}-${DEB_CUR} --package smithproxy
#dch -i --package smithproxy

#echo "Creating source archive"
#cd $CUR_DIR
#tar cvfz smithproxy_${VER}.orig.tar.gz smithproxy-${VER}/
#cd -

echo "Creating debian packages..."
#cd smithproxy-${VER}-${DEB_CUR}
debuild -us -uc

echo "cd to $CUR_DIR"
cd $CUR_DIR

echo "Archiving"
mkdir archives
tar cvfz archives/smithproxy_${VER}-${DEB_CUR}_${DISTRO}_build.tar.gz smithproxy_${VER}-${DEB_CUR}*

echo "Saving changelog"
cp -f smithproxy-${VER}/debian/changelog debian/

if [ "$UPLOAD_STREAMLINE_CHANGELOG" == "Y" ]; then
    echo "..uploading also streamline changelog, because this is its first build"
    curl -tlsv1.2 --ftp-ssl-control --ftp-create-dirs -T smithproxy-${VER}/debian/changelog -k ${UPLOAD_URL}/${VER_MAJ}/
fi


