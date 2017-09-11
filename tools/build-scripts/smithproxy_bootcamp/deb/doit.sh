DEB_MIN=`cat DEB_VERSION`
DEB_CUR=`expr  $DEB_MIN + 1`
VER=`cat VERSION`
VER_MAJ=`cat VERSION | awk -F. '{ print $1"."$2; }'`
DEB_DIR="smithproxy-$VER"
CUR_DIR=`pwd`
DISTRO=`./distro.sh`
UPLOAD_URL="ftp://mag0net_uploader:Tr3asur3Ch3st@ftp.mag0.net/web/out/smithproxy"
DOWNLOAD_URL="http://www.mag0.net/out/smithproxy"

DEBEMAIL="support@smithproxy.org"
DEBFULLNAME="Smithproxy Support"

echo "Preparing version ${VER}-${DEB_CUR}"
cp -rv debian $DEB_DIR

echo "cd to $DEB_DIR"
cd $DEB_DIR

echo "Filling changelog..."
export DEBEMAIL="$DEBEMAIL"
export DEBFULLNAME="$DEBFULLNAME"

wget ${DOWNLOAD_URL}/${DISTRO}/${VER_MAJ}/changelog -O debian/changelog.dnld
#wget ${DOWNLOAD_URL}/${DISTRO}/changelog -O debian/changelog

if [ ! -s debian/changelog.dnld ]; then
    echo "changelog doesn't exist on server, creating one"
    echo "smithproxy (${VER}-1) unstable; urgency=medium"   > debian/changelog
    echo ""                                                 >> debian/changelog
    echo "    * initial build for this version/platform"    >> debian/changelog
    echo ""                                                 >> debian/changelog
    echo "    -- Smithproxy Support <support@smithproxy.org>  `date -R`" >> debian/changelog
    echo ""                                                 >> debian/changelog
    
else
    echo "overwriting template changelog with downloaded one"
    cp -f debian/changelog.dnld debian/changelog
fi

dch -v ${VER}-${DEB_CUR} --package smithproxy
#dch -i --package smithproxy

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


