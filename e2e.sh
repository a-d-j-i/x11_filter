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
#   RIG_SERVER=xvfb    (default)  headless frame buffer
#   RIG_SERVER=xephyr             a genuine Xorg-derived server: the visuals,
#                                 RENDER and Composite a desktop client meets
#   RIG_SERVER=both               run under each in turn
#
#   RIG_WM=openbox     (default)  reparenting, no compositor
#   RIG_WM=metacity               reparenting *and* compositing, which is what
#                                 a desktop session actually looks like
#   RIG_WM=none                   bare server, no frames at all
#   RIG_WM=both                   run under openbox and metacity in turn
#
#   RIG_MENU_APPS="gedit code"    clients whose context menu must open *and*
#                                 answer the keyboard: opening one takes a grab
#                                 and navigating one takes the keys that grab
#                                 delivers, so between them they are the
#                                 interaction a policy change is most likely to
#                                 break
#   RIG_MENU_KEY=Down             the key the menu must respond to
#   RIG_DWELL=15                  watch each client this long after it maps (5)
#   RIG_COMPOSITE=0               run metacity without its compositor
#   RIG_PARENT="$DISPLAY"         nest Xephyr in your own display and watch it
#
# attack.sh reads the same RIG_* variables, so the same environment can drive
# either harness and the command is the only thing that changes.  The older
# E2E_* spellings still work here.
#
# The proxy is generic -- it filters whatever speaks the X protocol -- so any
# X client works here.  Needs python3, xauth, xwininfo, xdotool, xwd, bc,
# setsid and Xvfb or Xephyr -- each checked up front with what it is for --
# plus xclip for the clipboard checks, which are skipped without it.  Absent
# applications are skipped too.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
# Seconds to keep watching a client after its first window appears.  A window
# is not the same as a working client: a substituted reply can be malformed in
# a way the toolkit only trips over later -- a reply field that resolves to a
# NULL pointer inside Xlib, say -- so the client maps, then dies.  Without this
# the run would score that a PASS.
dwell="${RIG_DWELL:-${E2E_DWELL:-5}}"
composite="${RIG_COMPOSITE:-${E2E_COMPOSITE:-1}}"
par=":79"; up=":71"; px=":72"     # Xephyr's parent, upstream, and proxy
# ...and one more proxy, identical but for `--gate allow`.  The clipboard gate
# defaults to refusing a paste out, which is the right default and also means
# the default run can say nothing about what a *permitted* paste does.  The
# INCR path only exists on the permitted side, so it gets a display of its own
# rather than an environment variable somebody has to remember to set.
ax=":73"
up_auth="$work/up.auth"; px_auth="$work/px.auth"; ax_auth="$work/ax.auth"

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
    [ -n "${allower:-}" ] && kill "$allower" 2>/dev/null
    [ -n "${proxy:-}" ]  && kill "$proxy" 2>/dev/null
    [ -n "${wm:-}" ]     && kill "$wm" 2>/dev/null
    [ -n "${upsrv:-}" ]  && kill "$upsrv" 2>/dev/null
    [ -n "${parent:-}" ] && kill "$parent" 2>/dev/null
    proxy=""; wm=""; upsrv=""; parent=""; allower=""
    rm -f "/tmp/.X11-unix/X${up#:}" "/tmp/.X11-unix/X${px#:}" \
          "/tmp/.X11-unix/X${ax#:}" "/tmp/.X11-unix/X${par#:}"
}
cleanup() { teardown; rm -rf "$work"; }
trap cleanup EXIT
proxy=""; wm=""; upsrv=""; parent=""; allower=""

# Every tool the run leans on, checked before anything is started and named
# with what it is for.  A rig that dies half way through because xdotool is
# missing costs a minute and reports nothing -- and worse, a check that quietly
# did not run looks from the outside exactly like a check that passed.
need() {
    command -v "$1" >/dev/null && return 0
    echo "SKIP: $1 is not installed -- $2"
    [ -n "${3:-}" ] && echo "      Debian/Ubuntu: apt install $3"
    exit 0
}
# ...and the ones whose absence costs a check rather than the whole run.  These
# say what is lost and let the run continue, so what it does report still
# means what it says.
optional() {
    command -v "$1" >/dev/null && return 0
    echo "note: $1 is not installed -- $2"
    [ -n "${3:-}" ] && echo "      Debian/Ubuntu: apt install $3"
    return 1
}
need python3  "the proxy under test, and the harness's own helpers, are Python" python3
need xauth    "the throwaway displays are cookie-protected, and this writes their cookie files" xauth
need xwininfo "each client's window, and its geometry, is found by asking the server" x11-utils
need xdotool  "the menu check drives real pointer and keyboard input at the server" xdotool
need xwd      "the menu check dumps the window's own pixels to prove the menu really drew" x11-apps
need bc       "window areas are multiplied out, to tell a client's own window from its frame" bc
need setsid   "each client is started in its own session so it can be killed as a group" util-linux

# -- what to run, on which axes ---------------------------------------------
case "${RIG_SERVER:-${E2E_SERVER:-xvfb}}" in
    both)   servers=(xvfb xephyr) ;;
    xephyr) servers=(xephyr) ;;
    xvfb)   servers=(xvfb) ;;
    *)      echo "RIG_SERVER must be xvfb, xephyr or both"; exit 2 ;;
esac
case "${RIG_WM:-${E2E_WM:-openbox}}" in
    both)     managers=(openbox metacity) ;;
    metacity) managers=(metacity) ;;
    openbox)  managers=(openbox) ;;
    none)     managers=(none) ;;
    *)        echo "RIG_WM must be openbox, metacity, none or both"; exit 2 ;;
esac
for s in "${servers[@]}"; do
    [ "$s" = xephyr ] && need Xephyr
    # Xephyr draws into a window, so without RIG_PARENT it needs an Xvfb to
    # sit in -- which keeps the run headless either way.
    { [ "$s" = xvfb ] || [ -z "${RIG_PARENT:-${E2E_PARENT:-}}" ]; } && need Xvfb
done
for m in "${managers[@]}"; do
    [ "$m" = none ] || need "$m" \
        "RIG_WM asked for it; a reparenting window manager is what makes the
      toolkit send the requests this policy substitutes replies for. Set
      RIG_WM=none to run without one, knowing the run then covers less" \
        "$([ "$m" = openbox ] && echo openbox || echo metacity)"
done

cookie() { python3 -c 'import os; print(os.urandom(16).hex())'; }
# The set of top-level window ids on the real server.  Detecting a client's
# window by the *new* id it adds (not by a running count) is immune to a
# previous client's frame lingering as the next one starts.
win_ids() { DISPLAY="$up" XAUTHORITY="$up_auth" \
            xwininfo -root -children 2>/dev/null \
            | grep -oE '0x[0-9a-f]+' | sort -u; }

# Applications whose context menu must open.  Rendering is not the whole of
# "does the policy break real clients": a menu is the interaction most likely
# to break, because opening one takes a grab -- and a policy change that
# stopped GTK menus opening altogether went unnoticed here until it was
# measured by hand on a nested desktop.  Now it is measured every run.
menu_apps="${RIG_MENU_APPS-gedit}"

# Where a person's hands are.  With Xephyr the input goes to the *outer*
# display, so the nested server turns it into genuine device input; Xephyr's
# window is at the origin there, so the coordinates need no translation.
hands() {
    if [ -n "${input_display:-}" ]; then
        DISPLAY="$input_display" xdotool "$@"
    else
        DISPLAY="$up" XAUTHORITY="$up_auth" xdotool "$@"
    fi
}

# The largest of a set of window ids: the client's own window rather than the
# helper the window manager also created, which sorting by id picks up instead.
biggest_of() {
    local id area best best_area=0 line
    for id in $1; do
        line="$(DISPLAY="$up" XAUTHORITY="$up_auth" \
                xwininfo -id "$id" 2>/dev/null | grep -E '^  (Width|Height):')"
        [ -n "$line" ] || continue
        area=$(echo "$line" | awk '{print $2}' | paste -sd'*' | bc 2>/dev/null)
        [ -n "$area" ] || continue
        if [ "$area" -gt "$best_area" ]; then best_area="$area"; best="$id"; fi
    done
    echo "${best:-}"
}

# A raw dump of the screen.  xwd rather than a compressed screenshot: the bytes
# are the pixels, so a difference count means what it says.
# The window's own contents, not the root's: a compositing window manager
# redirects windows offscreen, so the root stops changing and a dump of it
# reports a menu that never moves.  Measured under metacity: zero bytes
# changed, zero noise -- the instrument was blind, not the menu broken.
snap() { DISPLAY="$up" XAUTHORITY="$up_auth" \
         xwd -id "$2" -silent > "$1" 2>/dev/null; }
changed() { cmp -l "$1" "$2" 2>/dev/null | wc -l; }

# Right-click the middle of the client's window, see whether a menu opens, and
# then whether it answers the keyboard.
#
# Both halves matter and only the first is obvious.  Opening a menu takes a
# grab; *navigating* one takes the keys that grab delivers, and a policy can
# perfectly well allow the menu to appear while the arrow keys go nowhere --
# which is exactly the shape of one fix this audit tried and withdrew.
#
#   0  the menu opened and took the keyboard
#   1  no menu opened
#   2  there was no window to click in
#   3  a menu opened but ignored the keyboard
# A big clipboard payload is the one thing a filtered application sends out in
# *chunks over time* rather than in one request.  Past a request's worth of
# data ICCCM switches to the INCR protocol: the owner answers with a type of
# INCR and then writes each chunk into the requestor's window -- foreign --
# waiting for a PropertyNotify back from it before sending the next.  Both of
# those are refused by default and allowed only by the selection grant, so this
# is the interaction where the grant's shape shows.  A small paste exercises
# none of it, which is the point of the size here.
#
# Twenty-sixth pass.  There was no clipboard check in this file at all until
# now, and that gap is why the grant's sixty seconds went twelve passes without
# anyone noticing it bounded the whole transfer rather than an idle one: a paste
# that took longer than that simply stopped half-way, and nothing in this file
# had ever pasted anything.  The timing itself is pinned by the unit tests, which can do it
# deterministically; what this adds is the proof that a real toolkit's INCR
# transfer crosses the proxy intact at all.
# Trust domains: `--domain` starts one and lives until stopped, `--use` and
# `--env` attach to it.  Checked here rather than in the unit tests because
# what is claimed is about processes and sockets -- that a second start finds
# the first rather than making a second trust domain wear the same name, that
# the display is derived (nothing was told to the second command), and that
# --stop actually stops it.
trust_domains() {
    local domain="e2e-domain-$$" broke=0 where="" again="" env_display=""
    # Started the way the shell helpers do it -- the proxy runs in the
    # foreground and the shell backgrounds it -- so this exercises the
    # documented path rather than a mode that exists only for tests.
    DISPLAY="$up" XAUTHORITY="$up_auth" python3 "$here/xfilter.py" \
        --domain "$domain" --upstream "$up" --upstream-auth "$up_auth" \
        >"$work/$domain.log" 2>&1 &
    for _ in $(seq 60); do
        where="$(python3 "$here/xfilter.py" --env "$domain" 2>/dev/null \
                 | sed -n 's/^export DISPLAY=//p')"
        [ -n "$where" ] && break
        sleep 0.25
    done
    if [ -z "$where" ]; then
        echo "FAIL  --domain did not start a filter"
        tail -3 "$work/$domain.log"
        return 1
    fi

    again="$(python3 "$here/xfilter.py" --domain "$domain" --upstream "$up" \
        2>&1 | grep -o ':[0-9]\+' | head -1)"
    if [ "$again" = "$where" ]; then
        echo "PASS  a second --domain found the first on $where"
    else
        echo "FAIL  --domain started a second filter for one name ($where then $again)"
        broke=1
    fi

    # The using side: nothing here was told where the domain lives.
    env_display="$(python3 "$here/xfilter.py" --env "$domain" \
                   | sed -n 's/^export DISPLAY=//p')"
    if [ "$env_display" = "$where" ]; then
        echo "PASS  --env derived the same display from the name alone"
    else
        echo "FAIL  --env gave '$env_display', not $where"
        broke=1
    fi
    if python3 "$here/xfilter.py" --use "$domain" -- xwininfo -root \
            >/dev/null 2>&1; then
        echo "PASS  --use ran a client on the domain's display"
    else
        echo "FAIL  --use could not run a client on the domain's display"
        broke=1
    fi

    # The safety property the derived display rests on: a *different* domain
    # that ends up looking at this display must be refused, not quietly let
    # in.  Forced here rather than waited for -- give the other domain a
    # cookie for this display, with the wrong value, which is exactly what a
    # hash collision would produce -- because two names sharing one filter is
    # the one outcome that must be impossible.
    local other="$domain-collides"
    python3 - "$here" "$other" "${where#:}" <<'PY'
import os, sys
sys.path.insert(0, sys.argv[1])
import xfilter, xfilter_core
xfilter_core.write_xauth_entry(xfilter.domain_auth(sys.argv[2]),
                               sys.argv[3], xfilter_core.COOKIE_NAME,
                               os.urandom(16))
PY
    if python3 "$here/xfilter.py" --env "$other" >/dev/null 2>&1; then
        echo "FAIL  a second domain attached to $where with its own cookie"
        broke=1
    else
        echo "PASS  a colliding domain was refused $where rather than joining it"
    fi
    rm -f "$(python3 -c "import sys; sys.path.insert(0, '$here'); import xfilter; print(xfilter.domain_auth('$other'))")"

    python3 "$here/xfilter.py" --stop "$domain" >/dev/null 2>&1
    if python3 "$here/xfilter.py" --env "$domain" >/dev/null 2>&1; then
        echo "FAIL  --stop left the filter running"
        broke=1
    else
        echo "PASS  --stop stopped it, and --env says so"
    fi
    return "$broke"
}

clipboard_out() {
    optional xclip \
        "the clipboard checks need a client that can hold a selection and read
      one back; without it nothing here exercises the gate or the INCR path" \
        xclip || { echo "skip  clipboard paste-out (no xclip)"; return 0; }
    kill -0 "${allower:-0}" 2>/dev/null || {
        echo "skip  clipboard paste-out (no --gate allow proxy)"; return 0; }
    local payload="$work/clip.in" got="$work/clip.out" owner="" size="" broke=0
    python3 -c "
import sys
sys.stdout.write(('a clipboard payload %s\\n' % ('x' * 44)) * 70000)
" > "$payload"
    size="$(wc -c < "$payload")"

    # permitted: the whole payload has to arrive, chunk by chunk
    DISPLAY="$ax" XAUTHORITY="$ax_auth" xclip -selection clipboard -i "$payload" \
        </dev/null >/dev/null 2>&1 & owner=$!
    sleep 2
    : > "$got"
    DISPLAY="$up" XAUTHORITY="$up_auth" timeout 90 xclip -o -selection clipboard \
        >"$got" 2>/dev/null
    kill "$owner" 2>/dev/null
    if cmp -s "$payload" "$got"; then
        echo "PASS  a $size-byte paste out of a permitted app arrived intact"
    else
        echo "FAIL  permitted paste-out: got $(wc -c < "$got" 2>/dev/null || echo 0) of $size bytes"
        broke=1
    fi

    # ...and refused, the gate has to stop the same payload rather than let a
    # big one through by a different road: taking the selection is refused, so
    # there is nothing upstream to paste.
    case " ${XFILTER_ARGS:-} " in
        *"--gate allow"*|*"--gate ask"*) return "$broke" ;;
    esac
    DISPLAY="$up" XAUTHORITY="$up_auth" xclip -selection clipboard -i /dev/null \
        </dev/null >/dev/null 2>&1 &
    local upstream_owner=$!
    sleep 1
    DISPLAY="$px" XAUTHORITY="$px_auth" xclip -selection clipboard -i "$payload" \
        </dev/null >/dev/null 2>&1 & owner=$!
    sleep 2
    : > "$got"
    DISPLAY="$up" XAUTHORITY="$up_auth" timeout 20 xclip -o -selection clipboard \
        >"$got" 2>/dev/null
    kill "$owner" "$upstream_owner" 2>/dev/null
    if cmp -s "$payload" "$got"; then
        echo "FAIL  the default gate let a $size-byte paste out anyway"
        broke=1
    else
        echo "PASS  the default gate refused the same paste out"
    fi
    return "$broke"
}

menu_opens() {
    local geometry x y before after noise signal floor key
    key="${RIG_MENU_KEY:-Down}"
    # By window id, not by pid: the client is started under setsid, so the pid
    # in hand is the group leader's rather than the application's, and
    # _NET_WM_PID does not match it.  The id is the one this run watched appear.
    geometry="$(DISPLAY="$up" XAUTHORITY="$up_auth" \
                xdotool getwindowgeometry --shell "$1" 2>/dev/null)"
    [ -n "$geometry" ] || return 2               # no window to click in
    eval "$geometry"
    x=$((X + WIDTH / 2)); y=$((Y + HEIGHT / 2))
    before="$(win_ids)"
    hands mousemove "$x" "$y" >/dev/null 2>&1
    sleep 0.4
    hands click 3 >/dev/null 2>&1
    sleep 1.5
    after="$(comm -13 <(printf '%s\n' "$before") <(win_ids))"
    if [ -z "$after" ]; then
        hands key Escape >/dev/null 2>&1
        return 1
    fi

    # The noise floor first: a caret blinks, a clock ticks, so "the screen
    # changed" on its own proves nothing.  Two shots with nothing pressed say
    # how much this screen moves by itself; the keypress has to beat that.
    local menu
    menu="$(biggest_of "$after")"
    [ -n "$menu" ] || menu="$1"
    snap "$work/menu.a" "$menu"; sleep 0.6; snap "$work/menu.b" "$menu"
    noise="$(changed "$work/menu.a" "$work/menu.b")"
    hands key "$key" >/dev/null 2>&1
    sleep 0.6
    snap "$work/menu.c" "$menu"
    signal="$(changed "$work/menu.b" "$work/menu.c")"
    hands key Escape >/dev/null 2>&1
    floor=$(( noise * 3 + 200 ))
    echo "      (menu keyboard: $signal bytes changed, noise $noise, needs $floor)" >&2
    [ "$signal" -gt "$floor" ] || return 3
    return 0
}

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
        local parent_display="${RIG_PARENT:-${E2E_PARENT:-}}"
        if [ -z "$parent_display" ]; then
            Xvfb "$par" -screen 0 1500x1050x24 >/dev/null 2>&1 & parent=$!
            for _ in $(seq 40); do
                [ -S "/tmp/.X11-unix/X${par#:}" ] && break; sleep 0.25
            done
            parent_display="$par"
        fi
        input_display="$parent_display"
        DISPLAY="$parent_display" Xephyr "$up" -screen 1280x900x24 \
            -auth "$up_auth" >"$work/server.err" 2>&1 & upsrv=$!
    else
        Xvfb "$up" -screen 0 1280x900x24 -auth "$up_auth" \
            >"$work/server.err" 2>&1 & upsrv=$!
        input_display=""
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

    : > "$ax_auth"; chmod 600 "$ax_auth"
    XAUTHORITY="$up_auth" python3 "$here/xfilter.py" --display "$ax" \
        --upstream "$up" --auth "$ax_auth" --upstream-auth "$up_auth" \
        --gate allow --log "$work/allow.log" \
        >"$work/allow.out" 2>"$work/allow.err" &
    allower=$!
    for _ in $(seq 40); do [ -S "/tmp/.X11-unix/X${ax#:}" ] && break; sleep 0.25; done

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
        ok=""; mapped=""
        for _ in $(seq 360); do      # up to ~90s, for a JVM/Electron cold start
            mapped="$(biggest_of "$(comm -13 <(printf '%s\n' "$before") <(win_ids))")"
            [ -n "$mapped" ] && { ok=1; break; }
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
                case " $menu_apps " in
                    *" $bin "*)
                        menu_opens "$mapped"; menu_status=$?
                        case "$menu_status" in
                            0) echo "PASS  $app opened a context menu and it took the keyboard" ;;
                            2) echo "note  $app: no window to click in" ;;
                            3) echo "FAIL  $app opened a menu that ignores the keyboard"
                               broken=$((broken + 1)) ;;
                            *) echo "FAIL  $app could not open a context menu"
                               broken=$((broken + 1)) ;;
                        esac ;;
                esac
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

    clipboard_out || broken=$((broken + 1))
    trust_domains || broken=$((broken + 1))

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
