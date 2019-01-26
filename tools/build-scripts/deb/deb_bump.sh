DEB_VER=`cat DEB_VERSION`
DEB_VER=`expr $DEB_VER + 1`

echo "${DEB_VER}" > DEB_VERSION

echo "Deb version bumped to $DEB_VER"
