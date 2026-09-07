#! /bin/bash
# Build the Debian package, into build/ rather than over your home directory.
#
#   ./package.sh              # -> build/xfilter_VERSION_all.deb
#   ./package.sh /tmp/debs    # somewhere else
#
# Two things are being avoided here.
#
# dpkg-buildpackage writes its artifacts to the *parent* of the tree it builds
# and has no option to change that: `dh_builddeb --destdir` moves the .deb
# alone, and then dpkg-genbuildinfo cannot find it and the build fails.  So
# this does not argue with the tool -- it gives it a different parent.
#
# And the package is 3.0 (quilt), which means the source is two pieces: an
# orig tarball holding the upstream tree *without* debian/, and the packaging
# on top.  So the tarball is built first, from this working tree, and the
# packaging is copied onto an unpacked copy of it.  What gets built is
# therefore exactly what the source package ships -- a file you forgot to
# commit is a build failure here rather than a missing feature later.
#
# The tarball is byte-reproducible for a given commit: sorted, no owners, and
# timestamps taken from the commit date rather than from the clock.  That is
# what lets the same release be rebuilt later and still match the checksum
# recorded in the .dsc.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/build}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

version="$(dpkg-parsechangelog -l "$here/debian/changelog" -S Version)"
upstream="${version%-*}"                       # 0.9-1 -> 0.9
tree="$out/xfilter-$upstream"
orig="$out/xfilter_$upstream.orig.tar.gz"

# An old unpacked tree would be built instead of this one.
rm -rf "$tree"
mkdir -p "$tree"

# The upstream side: this working tree, minus the packaging and the litter.
# The same list lives in .gitattributes as export-ignore, so a tarball made
# from a git tag comes out the same way.
tar -cf - -C "$here" \
    --exclude=./debian --exclude=./.github --exclude=./.git \
    --exclude=./.gitattributes --exclude=./.gitignore \
    --exclude=./.idea --exclude=./build --exclude=./e2e.local \
    --exclude=./__pycache__ --exclude='*.py[cod]' --exclude=./.ruff_cache \
    . | tar -xf - -C "$tree"

stamp="$(git -C "$here" log -1 --format=%ct 2>/dev/null || echo 0)"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$stamp" \
    -cf - -C "$out" "xfilter-$upstream" | gzip -9n > "$orig"

# ...and the packaging on top of a copy of it.
cp -a "$here/debian" "$tree/debian"

cd "$tree"
dpkg-buildpackage -us -uc                      # source and binary

# The unpacked copy has done its job, and leaving a second source tree lying
# around is the clutter this script exists to avoid.
cd "$out"
rm -rf "$tree"

echo
echo "built into $out:"
# Only this build's files.  Anything older in the directory is left alone --
# it might be a release someone is keeping.
for built in "$out/xfilter_$upstream.orig.tar.gz" "$out"/xfilter_"$version"*; do
    [ -e "$built" ] && echo "  $built"
done
