#! /bin/bash
# Build the rig attack.py needs, run it, tear it down.
#
#   ./attack.sh          # the attacks, direct and through the enforcing proxy
#
# e2e.sh answers "does the policy break real clients?"  This answers the other
# half -- "do the attacks the audit calls closed still fail?"  Every check runs
# twice: straight at the server (the control, which must succeed or the check
# proves nothing) and through the proxy (which must refuse).
#
#   ./attack.sh --dry-run    # the suite's own self-test: with the policy
#                            # enforcing nothing, every check must FAIL.  A
#                            # green suite that cannot go red proves nothing.
#
# The rig is selected with the **same variables e2e.sh reads**, so one
# environment drives either harness and the command is the only thing that
# changes:
#
#   RIG_SERVER=xvfb    (default)  headless frame buffer
#   RIG_SERVER=xephyr             a genuine Xorg-derived server: the visuals,
#                                 RENDER, XI2, and the Composite, DAMAGE,
#                                 MIT-SHM, RECORD and XTEST surface a real
#                                 desktop offers -- which decides what can be
#                                 attacked at all, since an attack is only
#                                 proven closed on a server that offers the
#                                 route it would take
#   RIG_SERVER=both               run the whole suite once per server
#
#   RIG_WM=openbox     (default)  reparenting, no compositor
#   RIG_WM=metacity               reparenting *and* compositing
#   RIG_WM=none                   bare server: the fullscreen checks then have
#                                 nobody to honour a fullscreen request, so
#                                 they report INCONCLUSIVE rather than pass
#   RIG_WM=both                   run under openbox and metacity in turn
#
#   RIG_COMPOSITE=0               run metacity without its compositor
#   RIG_PARENT="$DISPLAY"         nest Xephyr in your own display, so the
#                                 attacks can be watched as they are refused
#
# Xephyr is a window on another display, so with no RIG_PARENT it is nested in
# a headless Xvfb and the run stays unattended.  That costs nothing: the parent
# is only a canvas, and the nested server still hands its clients the full
# Xorg extension set.
#
# Needs python3, xauth, xdotool, xdpyinfo and Xvfb (or Xephyr), plus -- for the
# fullscreen checks -- openbox or metacity; each is checked up front with what
# it is for.  xsetroot is optional, and what it costs is printed when it is
# missing.  The older ATTACK_* spellings still work.
set -u

mode=""
[ "${1:-}" = "--dry-run" ] && mode="--dry-run"

composite="${RIG_COMPOSITE:-1}"
parent_wanted="${RIG_PARENT:-${ATTACK_PARENT:-}}"

case "${RIG_SERVER:-${ATTACK_SERVER:-xvfb}}" in
    both)   servers=(xvfb xephyr) ;;
    xephyr) servers=(xephyr) ;;
    xvfb)   servers=(xvfb) ;;
    *)      echo "RIG_SERVER must be xvfb, xephyr or both"; exit 2 ;;
esac
case "${RIG_WM:-${ATTACK_WM:-openbox}}" in
    both)     managers=(openbox metacity) ;;
    metacity) managers=(metacity) ;;
    openbox)  managers=(openbox) ;;
    none)     managers=(none) ;;
    *)        echo "RIG_WM must be openbox, metacity, none or both"; exit 2 ;;
esac

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
par=":69"                              # a canvas for Xephyr, when nothing else
up=":66"; px=":67"; allow=":68"        # upstream, enforcing proxy, --gate allow
up_auth="$work/up.auth"; px_auth="$work/px.auth"; allow_auth="$work/allow.auth"

# Every tool the suite leans on, checked before a server is started and named
# with what it is for.  A check that could not be mounted is not a check that
# passed, so the ones that only cost a single attack say so and let the run
# continue rather than exiting on it.
need() {
    command -v "$1" >/dev/null && return 0
    echo "SKIP: $1 is not installed -- $2"
    [ -n "${3:-}" ] && echo "      Debian/Ubuntu: apt install $3"
    exit 0
}
optional() {
    command -v "$1" >/dev/null && return 0
    echo "note: $1 is not installed -- $2"
    [ -n "${3:-}" ] && echo "      Debian/Ubuntu: apt install $3"
    return 1
}
need python3  "the attacks and the proxy they are aimed at are both Python" python3
need xauth    "the servers under attack are cookie-protected, and this writes their cookie files" xauth
need xdotool  "the attacks that need real input -- typing a secret, moving the pointer -- drive it at the server" xdotool
need xdpyinfo "the rig waits for each server to come up by asking it to describe itself" x11-utils
for wanted in "${servers[@]}"; do
    [ "$wanted" = xephyr ] && need Xephyr
    # Xephyr draws into a window, so with no parent display it needs an Xvfb to
    # sit in -- which keeps the run headless either way.
    { [ "$wanted" = xvfb ] || [ -z "$parent_wanted" ]; } && need Xvfb
done
for wanted in "${managers[@]}"; do
    [ "$wanted" = none ] || need "$wanted" \
        "RIG_WM asked for it, and \"did this window go fullscreen?\" is a
      question only a window manager can answer. Set RIG_WM=none to run
      without one, knowing the fullscreen checks are then INCONCLUSIVE" \
        "$([ "$wanted" = openbox ] && echo openbox || echo metacity)"
done

cleanup() {
    for pid in ${proxy_allow:-} ${proxy:-} ${wm:-} ${upsrv:-} ${parent:-}; do
        kill "$pid" 2>/dev/null
    done
    rm -rf "$work"
    rm -f "/tmp/.X11-unix/X${up#:}" "/tmp/.X11-unix/X${px#:}" \
          "/tmp/.X11-unix/X${allow#:}" "/tmp/.X11-unix/X${par#:}" \
          "/tmp/.X${up#:}-lock" "/tmp/.X${px#:}-lock" \
          "/tmp/.X${allow#:}-lock" "/tmp/.X${par#:}-lock"
}
trap cleanup EXIT
upsrv=""; parent=""; wm=""; proxy=""; proxy_allow=""

cookie() { python3 -c 'import os; print(os.urandom(16).hex())'; }

teardown() {                       # everything one server's run started
    for pid in ${proxy_allow:-} ${proxy:-} ${wm:-} ${upsrv:-} ${parent:-}; do
        kill "$pid" 2>/dev/null
    done
    proxy_allow=""; proxy=""; wm=""; upsrv=""; parent=""
    sleep 0.5
    rm -f "/tmp/.X11-unix/X${up#:}" "/tmp/.X11-unix/X${px#:}" \
          "/tmp/.X11-unix/X${allow#:}" "/tmp/.X11-unix/X${par#:}" \
          "/tmp/.X${up#:}-lock" "/tmp/.X${px#:}-lock" \
          "/tmp/.X${allow#:}-lock" "/tmp/.X${par#:}-lock"
}

start_proxy() {   # display auth logfile extra-args...
    local display="$1" auth="$2" log="$3"; shift 3
    python3 "$here/xfilter.py" --display "$display" --auth "$auth" \
        --upstream "$up" --upstream-auth "$up_auth" --log "$log" "$@" \
        >"$log.err" 2>&1 &
    for _ in $(seq 60); do
        [ -e "/tmp/.X11-unix/X${display#:}" ] && return 0
        sleep 0.2
    done
    echo "the proxy on $display did not start"; cat "$log.err"; return 1
}

run_against() {                    # server, window manager
    local server="$1" manager="$2" wm_label="$2" input_display=""
    : > "$up_auth"; chmod 600 "$up_auth"
    xauth -f "$up_auth" add "$up" MIT-MAGIC-COOKIE-1 "$(cookie)" 2>/dev/null

    if [ "$server" = xephyr ]; then
        # Xephyr is a window on another display.  Nest it in the caller's own
        # display if they offered one -- then the attacks are visible while
        # they run -- and otherwise in a headless Xvfb, which keeps the run
        # unattended without changing what the nested server offers a client.
        local parent_display="$parent_wanted"
        if [ -z "$parent_display" ]; then
            Xvfb "$par" -screen 0 1500x1050x24 >/dev/null 2>&1 & parent=$!
            for _ in $(seq 60); do
                [ -S "/tmp/.X11-unix/X${par#:}" ] && break; sleep 0.25
            done
            parent_display="$par"
        fi
        # Input is driven at the *outer* server: the nested one then turns it
        # into genuine device input for its clients, which is what a person at
        # a keyboard produces.  Driving XTEST at the nested server instead
        # tests a slightly different thing.
        input_display="$parent_display"
        DISPLAY="$parent_display" Xephyr "$up" -screen 1280x900x24 \
            -screen 640x480x24 -auth "$up_auth" \
            >"$work/server.log" 2>&1 & upsrv=$!
    else
        # A second screen, because a policy that knows only about the first
        # stops applying on it -- and two screens is an ordinary desktop.
        Xvfb "$up" -auth "$up_auth" -screen 0 1280x900x24 \
            -screen 1 640x480x24 >"$work/server.log" 2>&1 & upsrv=$!
    fi
    for _ in $(seq 60); do
        DISPLAY=$up XAUTHORITY=$up_auth xdpyinfo >/dev/null 2>&1 && break
        sleep 0.25
    done
    DISPLAY=$up XAUTHORITY=$up_auth xdpyinfo >/dev/null 2>&1 || {
        echo "SKIP: $server did not start"; cat "$work/server.log"; return 0; }

    # A window manager, because "did this window go fullscreen?" is a question
    # only a window manager can answer -- and a compositing one redirects every
    # frame offscreen, which changes what the capture attacks are aimed at.
    case "$manager" in
        metacity)
            if [ "$composite" = 1 ]; then
                wm_label="metacity --composite"
                DISPLAY=$up XAUTHORITY=$up_auth metacity --composite \
                    --sm-disable >/dev/null 2>&1 & wm=$!
            else
                wm_label="metacity --no-composite"
                DISPLAY=$up XAUTHORITY=$up_auth metacity --no-composite \
                    --sm-disable >/dev/null 2>&1 & wm=$!
            fi
            sleep 2 ;;
        openbox)
            DISPLAY=$up XAUTHORITY=$up_auth openbox >/dev/null 2>&1 & wm=$!
            sleep 1.5 ;;
        none)
            wm_label="no window manager"
            echo "note: with no window manager the fullscreen checks have"\
                 "nobody to honour a fullscreen request, so they will be"\
                 "INCONCLUSIVE" ;;
    esac

    # Something for the capture attacks to steal, painted on the root *itself*:
    # a window's contents underneath its children are undefined, so a marker
    # window would make the copy read back blank and the check would accuse the
    # policy wrongly.  After the window manager, which paints the root itself.
    optional xsetroot \
        "the root window is left unpainted, so a capture attack may read back
      a uniform screen; its direct control then proves nothing and the check
      reports INCONCLUSIVE rather than red" \
        x11-xserver-utils && \
        DISPLAY=$up XAUTHORITY=$up_auth xsetroot -mod 4 4 -fg white -bg navy

    : > "$work/ops.log"
    start_proxy "$px" "$px_auth" "$work/ops.log" ${mode:+$mode} || return 1
    proxy=$!
    start_proxy "$allow" "$allow_auth" "$work/allow.log" --gate allow \
        ${mode:+$mode} || return 1
    proxy_allow=$!

    echo
    echo "=== the attacks against $server + $wm_label ==="
    grep -h 'argument-inspected extensions' "$work/ops.log.err" 2>/dev/null \
        | sed 's/^/    /'
    [ -n "$mode" ] && echo "self-test: the policy is enforcing nothing, so every
check below must FAIL -- except 'forging a line of the operation log', which
stays green because sanitising the proxy's own output is not a policy decision
and applies in either mode."

    ATTACK_SELFTEST="${mode:+1}" \
    ATTACK_INPUT="$input_display" \
    ATTACK_UPSTREAM=$up ATTACK_UPSTREAM_AUTH=$up_auth \
    ATTACK_PROXY=$px ATTACK_PROXY_AUTH=$px_auth \
    ATTACK_ALLOW_PROXY=$allow ATTACK_ALLOW_AUTH=$allow_auth \
    ATTACK_LOG="$work/ops.log" \
        python3 "$here/attack.py"
    local outcome=$?

    echo
    echo "the proxy's own account of it:"
    sed -n 's/^new operation: /    /p' "$work/ops.log" | sort -u | head -30
    return $outcome
}

status=0
outcomes=()
for server in "${servers[@]}"; do
    for manager in "${managers[@]}"; do
        if run_against "$server" "$manager"; then
            outcomes+=("ok     $server + $manager")
        else
            outcomes+=("FAILED $server + $manager"); status=1
        fi
        teardown
    done
done

echo
echo "combinations run:"
printf '    %s\n' "${outcomes[@]}"
exit $status
