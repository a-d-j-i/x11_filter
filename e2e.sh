#! /bin/bash
# End-to-end test: run real X clients through the *enforcing* proxy on a
# throwaway server, and fail if the policy breaks any of them.  This is the
# guard that the default-deny allowlist stays wide enough for ordinary
# applications.
#
#   ./e2e.sh                     # small X clients, plus anything in e2e.local
#   ./e2e.sh xterm 'eog f.png'   # or just these, replacing both lists
#
# Two axes of the environment are selectable, because what a toolkit asks the
# server for depends on both.  Each defaults to the cheap setting; `both` runs
# the same clients once per value and reports a line per combination.
#
#   E2E_SERVER=xvfb    (default)  headless frame buffer
#   E2E_SERVER=xephyr             a genuine Xorg-derived server: the visuals,
#                                 RENDER and Composite a desktop client meets
#   E2E_SERVER=both               run under each in turn
#
#   E2E_WM=openbox     (default)  reparenting, no compositor
#   E2E_WM=metacity               reparenting *and* compositing, which is what
#                                 a desktop session actually looks like
#   E2E_WM=none                   bare server, no frames at all
#   E2E_WM=both                   run under openbox and metacity in turn
#
#   E2E_DWELL=15                  watch each client this long after it maps (5)
#   E2E_COMPOSITE=0               run metacity without its compositor
#   E2E_PARENT="$DISPLAY"         nest Xephyr in your own display and watch it
#
# The proxy is generic -- it filters whatever speaks the X protocol -- so any
# X client works here.  Needs xwininfo, xauth, and Xvfb or Xephyr; skips apps
# that are absent.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
# Seconds to keep watching a client after its first window appears.  A window
# is not the same as a working client: a substituted reply can be malformed in
# a way the toolkit only trips over later -- a reply field that resolves to a
# NULL pointer inside Xlib, say -- so the client maps, then dies.  Without this
# the run would score that a PASS.
dwell="${E2E_DWELL:-5}"
composite="${E2E_COMPOSITE:-1}"
par=":79"; up=":71"; px=":72"     # Xephyr's parent, upstream, and proxy
up_auth="$work/up.auth"; px_auth="$work/px.auth"

# Named clients replace the defaults entirely, so `./e2e.sh <app>` tests just
# that one.  With no arguments the default set runs, plus any extra targets you
# test locally but do not ship: one command per line in e2e.local (gitignored).
# That local file is where a heavy IDE or other private app goes, so it
# exercises the policy on your machine without its name entering the repo.
apps=("$@")
if [ ${#apps[@]} -eq 0 ]; then
    apps=(xeyes xclock xcalc xlogo)
    if [ -f "$here/e2e.local" ]; then
        while IFS= read -r line; do
            case "$line" in ''|'#'*) ;; *) apps+=("$line") ;; esac
        done < "$here/e2e.local"
    fi
fi

teardown() {                      # everything one combination started
    [ -n "${proxy:-}" ]  && kill "$proxy" 2>/dev/null
    [ -n "${wm:-}" ]     && kill "$wm" 2>/dev/null
    [ -n "${upsrv:-}" ]  && kill "$upsrv" 2>/dev/null
    [ -n "${parent:-}" ] && kill "$parent" 2>/dev/null
    proxy=""; wm=""; upsrv=""; parent=""
    rm -f "/tmp/.X11-unix/X${up#:}" "/tmp/.X11-unix/X${px#:}" \
          "/tmp/.X11-unix/X${par#:}"
}
cleanup() { teardown; rm -rf "$work"; }
trap cleanup EXIT
proxy=""; wm=""; upsrv=""; parent=""

need() { command -v "$1" >/dev/null || { echo "SKIP: $1 not installed"; exit 0; }; }
need xwininfo; need xauth

# -- what to run, on which axes ---------------------------------------------
case "${E2E_SERVER:-xvfb}" in
    both)   servers=(xvfb xephyr) ;;
    xephyr) servers=(xephyr) ;;
    xvfb)   servers=(xvfb) ;;
    *)      echo "E2E_SERVER must be xvfb, xephyr or both"; exit 2 ;;
esac
case "${E2E_WM:-openbox}" in
    both)     managers=(openbox metacity) ;;
    metacity) managers=(metacity) ;;
    openbox)  managers=(openbox) ;;
    none)     managers=(none) ;;
    *)        echo "E2E_WM must be openbox, metacity, none or both"; exit 2 ;;
esac
for s in "${servers[@]}"; do
    [ "$s" = xephyr ] && need Xephyr
    # Xephyr draws into a window, so without E2E_PARENT it needs an Xvfb to
    # sit in -- which keeps the run headless either way.
    { [ "$s" = xvfb ] || [ -z "${E2E_PARENT:-}" ]; } && need Xvfb
done
for m in "${managers[@]}"; do
    [ "$m" = none ] || command -v "$m" >/dev/null || {
        echo "SKIP: $m not installed"; exit 0; }
done

cookie() { python3 -c 'import os; print(os.urandom(16).hex())'; }
# The set of top-level window ids on the real server.  Detecting a client's
# window by the *new* id it adds (not by a running count) is immune to a
# previous client's frame lingering as the next one starts.
win_ids() { DISPLAY="$up" XAUTHORITY="$up_auth" \
            xwininfo -root -children 2>/dev/null \
            | grep -oE '0x[0-9a-f]+' | sort -u; }

# -- one combination of server and window manager ---------------------------
# Returns the number of clients the policy broke, or 255 if the harness itself
# failed to stand up -- the two must not be confused, since one is a finding
# about the policy and the other is a broken test rig.  Leaves its operation
# log in $work/ops.log for the caller to report.
run_combination() {
    local server="$1" manager="$2" wm_label="$2"
    rm -f "/tmp/.X11-unix/X${up#:}" "/tmp/.X11-unix/X${px#:}" \
          "/tmp/.X11-unix/X${par#:}"
    : > "$up_auth"; chmod 600 "$up_auth"
    : > "$px_auth"; chmod 600 "$px_auth"
    : > "$work/ops.log"
    xauth -f "$up_auth" add "$up" MIT-MAGIC-COOKIE-1 "$(cookie)"

    if [ "$server" = xephyr ]; then
        local parent_display="${E2E_PARENT:-}"
        if [ -z "$parent_display" ]; then
            Xvfb "$par" -screen 0 1500x1050x24 >/dev/null 2>&1 & parent=$!
            for _ in $(seq 40); do
                [ -S "/tmp/.X11-unix/X${par#:}" ] && break; sleep 0.25
            done
            parent_display="$par"
        fi
        DISPLAY="$parent_display" Xephyr "$up" -screen 1280x900x24 \
            -auth "$up_auth" >"$work/server.err" 2>&1 & upsrv=$!
    else
        Xvfb "$up" -screen 0 1280x900x24 -auth "$up_auth" \
            >"$work/server.err" 2>&1 & upsrv=$!
    fi
    for _ in $(seq 60); do [ -S "/tmp/.X11-unix/X${up#:}" ] && break; sleep 0.25; done
    [ -S "/tmp/.X11-unix/X${up#:}" ] || {
        echo "ERROR: $server did not start"; cat "$work/server.err"; return 255; }

    # A reparenting window manager wraps every client in a frame the client
    # does not own, and a compositor redirects those frames offscreen.  Both
    # change which requests a toolkit sends about windows it did not create --
    # which is exactly the surface this policy substitutes replies for.
    case "$manager" in
        metacity)
            if [ "$composite" = 1 ]; then
                wm_label="metacity --composite"
                DISPLAY="$up" XAUTHORITY="$up_auth" metacity --composite \
                    --sm-disable >"$work/wm.err" 2>&1 & wm=$!
            else
                DISPLAY="$up" XAUTHORITY="$up_auth" metacity --no-composite \
                    --sm-disable >"$work/wm.err" 2>&1 & wm=$!
            fi
            sleep 2 ;;
        openbox)
            DISPLAY="$up" XAUTHORITY="$up_auth" openbox \
                >"$work/wm.err" 2>&1 & wm=$!
            sleep 1 ;;
        none) wm_label="no window manager" ;;
    esac
    echo "== $server + $wm_label =="

    # XFILTER_ARGS passes extra policy flags through, so a stricter setting can
    # be tried against the same clients without editing this file:
    #     XFILTER_ARGS='--gate allow' ./e2e.sh
    XAUTHORITY="$up_auth" python3 "$here/xfilter.py" --display "$px" \
        --upstream "$up" --auth "$px_auth" --upstream-auth "$up_auth" \
        --log "$work/ops.log" ${XFILTER_ARGS:-} \
        >"$work/proxy.out" 2>"$work/proxy.err" &
    proxy=$!
    for _ in $(seq 40); do [ -S "/tmp/.X11-unix/X${px#:}" ] && break; sleep 0.25; done
    kill -0 "$proxy" 2>/dev/null || {
        echo "ERROR: proxy did not start"; cat "$work/proxy.err"; return 255; }

    local broken=0 app bin before home pid ok
    for app in "${apps[@]}"; do
        bin="${app%% *}"
        command -v "$bin" >/dev/null || { echo "skip  $app (not installed)"; continue; }
        before="$(win_ids)"
        # A fresh HOME per client: harmless for small apps, and it keeps a
        # heavy IDE from touching real config or a running instance's
        # single-instance lock.  The poll below still returns the moment a
        # window appears, so a fast client is not slowed by the long ceiling a
        # slow one needs.
        home="$work/home"; rm -rf "$home"; mkdir -p "$home/run"; chmod 700 "$home/run"
        # A private HOME *and* private XDG dirs: this is what keeps a heavy IDE
        # from finding the config/lock of an instance you already have running
        # and handing off to it -- it starts a clean, separate instance
        # instead.  setsid puts it in its own process group so its JVM/helpers
        # tear down as a group.
        HOME="$home" \
            XDG_CONFIG_HOME="$home/.config" XDG_CACHE_HOME="$home/.cache" \
            XDG_DATA_HOME="$home/.local/share" XDG_STATE_HOME="$home/.local/state" \
            XDG_RUNTIME_DIR="$home/run" \
            DISPLAY="$px" XAUTHORITY="$px_auth" setsid $app >/dev/null 2>&1 &
        pid=$!
        ok=""
        for _ in $(seq 360); do      # up to ~90s, for a JVM/Electron cold start
            [ -n "$(comm -13 <(printf '%s\n' "$before") <(win_ids))" ] && { ok=1; break; }
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.25
        done
        if [ -n "$ok" ]; then
            # It mapped a window -- now see whether it survives being on screen.
            for _ in $(seq $((dwell * 4))); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.25
            done
            if kill -0 "$pid" 2>/dev/null; then
                echo "PASS  $app rendered and stayed up under enforce"
            else
                echo "FAIL  $app rendered, then died within ${dwell}s under the policy"
                broken=$((broken + 1))
            fi
        else
            echo "FAIL  $app produced no window under the policy"
            broken=$((broken + 1))
        fi
        kill -- -"$pid" 2>/dev/null || kill "$pid" 2>/dev/null   # the whole group
        for _ in $(seq 12); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
    done

    echo "operations the policy blocked:"
    if grep -qF ' blocked ' "$work/ops.log" 2>/dev/null; then
        grep -F ' blocked ' "$work/ops.log" | awk '{print "   ", $3}' | sort -u
    else
        echo "    (none)"
    fi
    return "$broken"
}

# -- the matrix --------------------------------------------------------------
fails=0
harness_errors=0
summary=()
for server in "${servers[@]}"; do
    for manager in "${managers[@]}"; do
        run_combination "$server" "$manager"
        broken=$?
        teardown
        if [ "$broken" -eq 255 ]; then
            harness_errors=$((harness_errors + 1))
            summary+=("ERROR  $server + $manager (harness did not start)")
        elif [ "$broken" -eq 0 ]; then
            summary+=("ok     $server + $manager")
        else
            fails=$((fails + broken))
            summary+=("BROKE  $server + $manager ($broken client(s))")
        fi
        echo
    done
done

if [ ${#summary[@]} -gt 1 ]; then
    echo "combinations run:"
    printf '    %s\n' "${summary[@]}"
    echo
fi
if [ "$harness_errors" -gt 0 ]; then
    echo "e2e: $harness_errors combination(s) could not be stood up -- the test"
    echo "     rig failed, so this says nothing about the policy"
    exit 2
elif [ "$fails" -eq 0 ]; then
    echo "e2e: all clients rendered under the enforcing policy"
    exit 0
else
    echo "e2e: $fails client run(s) were broken by the policy"
    exit 1
fi
