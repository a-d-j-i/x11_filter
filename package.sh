#! /bin/bash
# Build the Debian package, into build/ rather than over your home directory.
#
#   ./package.sh              # -> build/xfilter_VERSION_all.deb
#   ./package.sh /tmp/debs    # somewhere else
#
# dpkg-buildpackage writes its artifacts to the *parent* of the tree it
# builds, and there is no option to change that: `dh_builddeb --destdir` moves
# the .deb alone, and then dpkg-genbuildinfo cannot find it and the build
# fails.  So this does not argue with the tool -- it gives it a different
# parent.  A source package is built into the output directory, unpacked
# there, and that copy is what gets built, so the parent is build/ and every
# artifact lands in it.
#
# The detour pays for itself: building the unpacked source package tests what
# the package actually *ships*, which a build in place cannot do.  A file you
# forgot to list is a build failure here and a missing feature later.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/build}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

version="$(dpkg-parsechangelog -l "$here/debian/changelog" -S Version)"
tree="$out/xfilter-$version"

# An old unpacked tree would be built instead of this one.  dpkg-source
# refuses to overwrite it rather than guess, so clear it first.
rm -rf "$tree"

cd "$out"
dpkg-source -b "$here"
dpkg-source -x "xfilter_$version.dsc"

cd "$tree"
dpkg-buildpackage -us -uc -b

# The unpacked copy has done its job, and leaving a second source tree lying
# around is the clutter this script exists to avoid.
cd "$out"
rm -rf "$tree"

echo
echo "built into $out:"
ls -1 "$out"/xfilter_"$version"* | sed 's|^|  |'
