BBT_USER="astibal"
SMITHPROXY_BRANCH="master"
SOCLE_BRANCH="master"

#SMITHPROXY_BRANCH="0.4"
#SOCLE_BRANCH="0.1"

P="smithproxy_${SMITHPROXY_BRANCH}_sl_${SOCLE_BRANCH}"
if [ -d ${P} ]; then
  echo "Directory already exists. Due to security remove it yourself if needed."
  exit
else
  echo "Creating ${P}"
  mkdir ${P} && cd ${P}
  echo "Moving to `pwd`"
  git clone git@bitbucket.org:${BBT_USER}/smithproxy.git -b ${SMITHPROXY_BRANCH}
  git clone git@bitbucket.org:${BBT_USER}/socle.git -b ${SOCLE_BRANCH}
fi
