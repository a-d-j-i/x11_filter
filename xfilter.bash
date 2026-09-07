# xfilter shell helpers -- source this from ~/.bashrc (or ~/.zshrc):
#
#     . /usr/share/xfilter/xfilter.bash        # packaged
#     . ~/src/x11_filter/xfilter.bash          # from a clone
#
# It defines one command:
#
#     xssh work@buildbox [cmd...]   ssh there through that domain's filter
#
# One, because the proxy's own two verbs are already short and say what they
# do -- `xfilter.py --list`, `--stop NAME`, `--domain NAME` -- and a wrapper
# that saves six characters costs a name you have to remember.  What `xssh`
# adds is the one thing the proxy deliberately will not do for you: start a
# filter and use it in the same breath.  That is a convenience, and
# conveniences belong somewhere you can read and change them.

# The command: a full path, worked out once, here.
#
# Not the bare name this used to be.  A shell remembers where it first found a
# command and keeps using that path without looking again, so when an install
# moves -- a clone replaced by a package, say -- an old shell goes on trying
# the path that is no longer there, and the failure names a file nobody typed.
# Resolving once, at source time, puts the answer somewhere you can read:
# `echo $XFILTER`.
#
# The search walks PATH here rather than asking the shell, because the shell
# answers out of that same memory: `command -v` will name a file that was
# deleted an hour ago, which is the problem rather than the fix.
#
# Set XFILTER yourself to override.  A name is looked up on PATH, a path is
# taken as given -- which is how you point these helpers at a clone.
_xfilter_lookup() {
    local dir rest
    case "$1" in
        */*) [ -x "$1" ] || return 1; printf '%s' "$1"; return 0 ;;
    esac
    rest="$PATH"
    while [ -n "$rest" ]; do
        dir="${rest%%:*}"
        [ "$dir" = "$rest" ] && rest="" || rest="${rest#*:}"
        if [ -x "${dir:-.}/$1" ]; then printf '%s' "${dir:-.}/$1"; return 0; fi
    done
    return 1
}

if [ -n "${XFILTER:-}" ]; then
    XFILTER="$(_xfilter_lookup "$XFILTER" || printf '%s' "$XFILTER")"
else
    XFILTER="$(_xfilter_lookup xfilter.py || _xfilter_lookup xfilter \
               || printf '%s' xfilter.py)"
fi
unset -f _xfilter_lookup          # source-time only; not a name to leave behind

# Nothing was found, or what was named is not there.  Say so at once: the
# alternative is silence now and a puzzling fifteen-second wait later, for a
# filter that was never going to start.
[ -x "$XFILTER" ] || echo "xfilter.bash: no proxy at '$XFILTER' --" \
    "install xfilter, or set XFILTER to the path of xfilter.py" >&2

# Which display new filters forward *to*, captured once when this file is
# sourced.  Deliberately not "whatever DISPLAY says at the time": a shell that
# has been pointed at a filtered display would otherwise start the next filter
# in front of the first one, quietly chaining two proxies.
: "${XF_UPSTREAM:=$DISPLAY}"

# Default gate for filters these helpers start.  `ask` is the setting that
# gives you a clipboard in both directions, at one prompt per connection.
: "${XF_GATE:=ask}"

# Where a backgrounded filter's output goes.  The shell starts it, so the
# shell keeps its log -- the proxy has no --detach and no opinion about this.
: "${XF_LOGDIR:=${XDG_RUNTIME_DIR:-/tmp}/xfilter-${UID:-$(id -u)}}"

# Start the filter for a trust domain, or confirm the one already running.
# Internal: xssh is the command, this is how it gets its display.  Call it
# directly if you want a domain that is not an ssh target -- one around a
# local application you will then run with `xfilter.py --use` -- or just run
# `xfilter.py --domain NAME &` yourself, which is all this is.
#
# Safe to call every time: a second call is a no-op, not a second domain.
#
# `xfilter --domain` runs in the foreground and lives until it is stopped,
# which is what lets a terminal or a systemd unit own it.  Here we want it in
# the background, so this does what a shell does: `&`, then wait until the
# using side can actually answer, because "the process started" and "the
# display works" are not the same claim.
_xfilter_up() {
    local domain="${1:?usage: _xfilter_up DOMAIN}" log=""
    if [ ! -x "$XFILTER" ]; then                  # nothing to start: say so now
        echo "xssh: no proxy at $XFILTER -- set XFILTER, or install xfilter" >&2
        return 1
    fi
    "$XFILTER" --env "$domain" >/dev/null 2>&1 && return 0    # already up

    mkdir -p "$XF_LOGDIR" 2>/dev/null
    log="$XF_LOGDIR/${domain//[^A-Za-z0-9._@-]/_}.log"
    "$XFILTER" --domain "$domain" --gate "$XF_GATE" \
               --upstream "$XF_UPSTREAM" >>"$log" 2>&1 &
    disown 2>/dev/null

    local waited=0
    while [ "$waited" -lt 60 ]; do
        "$XFILTER" --env "$domain" >/dev/null 2>&1 && return 0
        sleep 0.25
        waited=$((waited + 1))
    done
    echo "xssh: the filter for $domain did not start -- see $log" >&2
    tail -3 "$log" >&2 2>/dev/null
    return 1
}

# ssh somewhere through its own filter.
#
# The environment is scoped to this one ssh -- your shell's DISPLAY is left
# alone on purpose.  Exporting a domain into a shell leaves it there after you
# have forgotten about it, and the next thing you start in that shell would
# silently join a trust domain it has nothing to do with.
xssh() {
    local domain="${1:?usage: xssh [user@]host [command...]}"; shift
    _xfilter_up "$domain" >/dev/null || return
    "$XFILTER" --use "$domain" -- \
        ssh -X -o ForwardX11Trusted=yes "$domain" "$@"
}

# ...and for the rest, the proxy is the command:
#
#     xfilter.py --list                what is running
#     xfilter.py --stop work@buildbox  stop one
#     xfilter.py --use NAME -- cmd     run one command on a domain's display
