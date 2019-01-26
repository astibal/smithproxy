# mark branches you want to build
SOCLE_BRANCH=master
SMITHPROXY_BRANCH=master

# clean it!
./clean.sh

git clone http://bitbucket.org/astibal/smithproxy.git smithproxy
cd smithproxy; git fetch; git checkout $SMITHPROXY_BRANCH; cd ..

git clone http://bitbucket.org/astibal/socle.git socle
cd socle; git fetch; git checkout $SOCLE_BRANCH; cd ..

VERSION=`cat smithproxy/smithproxy.hpp | awk -F\" '{ print \$2 }' | strings`
echo "Cloned version from sources is $VERSION ."
mv smithproxy smithproxy-${VERSION} 

if [ "${VERSION}" != "`cat VERSION`" ]; then
   echo "Version bump detected. Zeroize deb version."
   ./deb_zeroize.sh
    echo $VERSION > VERSION
    
else
   if [ "$1" == "bump" ]; then
       echo "Build sync forced => incrementing deb version."
       ./deb_bump.sh
   fi
fi

# create orig tarball
tar cfz smithproxy_`cat VERSION`.orig.tar.gz --exclude-vcs smithproxy-`cat VERSION`

