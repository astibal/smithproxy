DEB_MIN=`cat DEB_VERSION`
DEB_CUR=`expr  $DEB_MIN + 1`
VER=`cat VERSION`
VER_MAJ=`cat VERSION | awk -F. '{ print $1"."$2; }'`
DEB_DIR="smithproxy-$VER"
CUR_DIR=`pwd`
DISTRO=`./distro.sh`
UPLOAD_URL="ftp://mag0net_uploader:Tr3asur3Ch3st@ftp.mag0.net/web/out/smithproxy"
DOWNLOAD_URL="http://www.mag0.net/out/smithproxy"

DEBEMAIL=astib@mag0.net
DEBFULLNAME="Ales Stibal"

echo "Compiler check.."
( g++ -v ) 2>&1 | grep 'gcc version 4.9' > /dev/null
if [ $? -ne 0 ]; then
  echo "We currently support only GCC/G++ 4.9, due to regex implementation in STL."
  echo "If you have G++ 4.9 installed, please ensure it's default compiler on your system."
  exit
fi


echo "Preparing version ${VER}-${DEB_CUR}"
cp -rv debian $DEB_DIR

echo "cd to $DEB_DIR"
cd $DEB_DIR

echo "Filling changelog..."
export DEBEMAIL="$DEBEMAIL"
export DEBFULLNAME="$DEBFULLNAME"

wget ${DOWNLOAD_URL}/${DISTRO}/${VER_MAJ}/changelog -O debian/changelog
#wget ${DOWNLOAD_URL}/${DISTRO}/changelog -O debian/changelog

dch -v ${VER}-${DEB_CUR} --package smithproxy
#dch -i --package smithproxy

echo "Creating debian packages..."
#cd smithproxy-${VER}-${DEB_CUR}
debuild -us -uc

echo "cd to $CUR_DIR"
cd $CUR_DIR

echo "Archiving"
tar cvfz archives/smithproxy_${VER}-${DEB_CUR}_${DISTRO}_build.tar.gz smithproxy_${VER}-${DEB_CUR}*

echo "Saving changelog"
cp -f smithproxy-${VER}/debian/changelog debian/


if [ "$1" == "upload" ]; then
    echo "File(s) being uploaded now."
    curl -tlsv1.2 --ftp-ssl-control --ftp-create-dirs -T smithproxy_${VER}-${DEB_CUR}*.deb -k ${UPLOAD_URL}/${DISTRO}/${VER_MAJ}/
    curl -tlsv1.2 --ftp-ssl-control --ftp-create-dirs -T debian/changelog -k ${UPLOAD_URL}/${DISTRO}/${VER_MAJ}/
    echo "Uploaded."
fi
