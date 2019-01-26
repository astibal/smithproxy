DEB_MIN=`cat DEB_VERSION`
DEB_CUR=`expr  $DEB_MIN + 1`
VER=`cat VERSION`
VER_MAJ=`cat VERSION | awk -F. '{ print $1"."$2; }'`
DEB_DIR="smithproxy-$VER"
CUR_DIR=`pwd`
DISTRO=`./distro.sh`
DOWNLOAD_URL="http://www.mag0.net/out/smithproxy"
PYLIBCONFIG2_FILE="python-pylibconfig2_0.2.5-1_all.deb"
UPLOAD_PWD=''

read -s -p "Enter upload password: " UPLOAD_PWD
UPLOAD_URL="ftp://mag0net_uploader:${UPLOAD_PWD}@ftp.mag0.net/web/out/smithproxy"

DEBEMAIL="support@smithproxy.org"
DEBFULLNAME="Smithproxy Support"

echo "Downloading pylibconfig2 package"
wget https://bitbucket.org/astibal/smithproxy/downloads/${PYLIBCONFIG2_FILE} -O ${PYLIBCONFIG2_FILE}

echo "File(s) being uploaded now."
curl -tlsv1.2 --ftp-ssl-control --ftp-create-dirs -T smithproxy_${VER}-${DEB_CUR}*.deb -k ${UPLOAD_URL}/${VER_MAJ}/${DISTRO}/
curl -tlsv1.2 --ftp-ssl-control --ftp-create-dirs -T smithproxy-${VER}/debian/changelog -k ${UPLOAD_URL}/${VER_MAJ}/${DISTRO}/
curl -tlsv1.2 --ftp-ssl-control --ftp-create-dirs -T ${PYLIBCONFIG2_FILE} -k ${UPLOAD_URL}/${VER_MAJ}/${DISTRO}/
curl -tlsv1.2 --ftp-ssl-control --ftp-create-dirs -T README -k ${UPLOAD_URL}/${VER_MAJ}/${DISTRO}/
echo "Uploaded."

