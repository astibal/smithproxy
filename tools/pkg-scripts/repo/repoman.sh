#
# This script will iterate package directory structure and generates
# Debian repository files.
#
# Repository structure:
# REPO_ROOT/<Distro_Version>/<snapshots|release>/binary-<arch>/
#
# Written as part of smithproxy project infrastructure.
# (c) Ales Stibal, astib@mag0.net


REPO_ROOT="/var/www/html/smithproxy"

if [ "$1" == "" ]; then
    echo "Missing key ID argument"
    exit 1
fi

REPO_KEY="$1"

LINUX_VERSIONS="Linux-Ubuntu-22.04 Linux-Ubuntu-20.04"
COMPONENTS="snapshots release"

cd "${REPO_ROOT}"
for DIR in $LINUX_VERSIONS; do

    cd "${REPO_ROOT}/${DIR}" || exit 1
    echo "Processing ${REPO_ROOT}/${DIR}"


    for COMP in $COMPONENTS; do
       echo "Processing component ${REPO_ROOT}/${DIR}/${COMP}"

        dpkg-scanpackages "${COMP}" /dev/null  > "${COMP}"/Packages
        # cat "${COMP}/Packages" | gzip -9c > "${COMP}/Packages.gz"

        cat "${REPO_ROOT}/.release.header" | sed -e "s/XXX/${COMP}/" | sed -e "s/YYY/${DIR}/" > "${COMP}/Release"
        apt-ftparchive release "${COMP}" >> "${COMP}/Release"


        gpg --yes -u "${REPO_KEY}" --clearsign -o "${COMP}/InRelease" "${COMP}/Release"
        gpg --yes -u "${REPO_KEY}" -abs -o "${COMP}/Release.gpg" "${COMP}/Release"
    done

done
