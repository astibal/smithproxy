# clean it!
./clean.sh

# create a clone of smithproxy directory
# git clone -l ../smithproxy/ smithproxy-git

git clone git@bitbucket.org:astibal/smithproxy.git smithproxy-git
git clone git@bitbucket.org:astibal/socle.git socle

VERSION=`cat smithproxy-git/smithproxy.hpp | awk -F\" '{ print \$2 }' | strings`
echo "Cloned version from sources is $VERSION ."

if [ "${VERSION}" != "`cat VERSION`" ]; then
   echo "Version bump detected. Zeroize deb version."
   ./deb_zeroize.sh
else
   if [ "$1" == "bump" ]; then
       echo "Build sync forced => incrementing deb version."
       ./deb_bump.sh
   elif [ "$1" == "rebuild" ]; then
       echo "Build will be redone, no changes to deb version."
   else
       echo "Nothing to be done, we are on the same version"
       exit -1
   fi
fi

echo $VERSION > VERSION

mv smithproxy-git smithproxy-${VERSION} 

# create orig tarball
tar cfz smithproxy_`cat VERSION`.orig.tar.gz --exclude-vcs smithproxy-`cat VERSION`

