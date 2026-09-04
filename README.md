# xfilter — a filtering X11 proxy

Remote applications forwarded over `ssh -X` are ordinary clients of your X
server, with everything that implies: they can read your clipboard, capture
your screen, log your keystrokes and enumerate your windows. `xfilter` sits
between them and your display and refuses the parts you did not agree to,
while leaving the drawing path untouched — applications still render natively
on your real server, at full speed, with correct cursors and theming.

```
remote host                              your desktop
  app ──► localhost:10 ──► sshd ══ssh══► ssh ──► :20 (xfilter) ──► :0
```

> **Experimental.** This is a hand-written filter for a protocol with a very
> large surface, built and tuned by profiling a handful of applications. The
> policy is default-deny, so a request type nobody thought of is blocked and
> logged rather than passed — but the allowlist *is* the boundary, and it was
> drawn by measuring real applications. Treat it as a useful reduction of
> exposure for a remote client you semi-trust, not as a containment jail for
> code you do not. It also assumes the filtered client cannot reach your
> server any other way; see **Limits**.

## When this is worth using

The case for it is narrow and specific: **you want the native `ssh -X`
experience but do not fully trust the machine you are forwarding from.**

Forwarded applications draw directly on your real X server, so they stay fast,
keep real cursors and theming, and behave exactly like local windows — while
being unable to read your clipboard, capture your screen, or type into your
session. Reach for it when:

- the remote host has other users, or runs code you did not write — a build
  server, a shared development box, an IDE pulling in dependencies;
- you tried `ForwardX11Trusted no`, found it broke cursors and themes, and then
  discovered it never protected your clipboard anyway (see below);
- you want to know what a remote application actually asks your display for —
  `--dry-run` answers that with no policy at all.

## When something else is the better answer

- **You trust the remote host.** Then plain `ssh -X` is fine and this only adds
  moving parts.
- **You need real isolation from hostile code.** Use a remote-display stack
  instead — `x2go`/`nxagent`, or `xpra`. Those terminate the X connection
  entirely, so nothing the application does reaches your server; the boundary
  is architectural rather than a list of rules. The cost is that output is
  re-rendered rather than drawn natively, which hurts GL and video.
- **You want to sandbox local applications.** This filters one display that you
  point clients at; local clients keep talking to `:0` directly.

## Why not just use untrusted forwarding

Because `ForwardX11Trusted no` does not do what its name suggests. Read from
the `xorg-server` 21.1.16 source, and confirmed by measurement:

- `Xext/security.c` registers nine XACE callbacks and `XACE_SELECTION_ACCESS`
  is not among them. The hook is live — `dix/selection.c` calls it on every
  selection operation — but only XSELinux ever registers for it. **Untrusted
  clients read your clipboard freely.**
- `SecurityProperty` permits `DixReadAccess` unconditionally, so untrusted
  clients read any `WM_*` property on anyone's window. Window titles and
  command lines leak.
- The SecurityPolicy file that used to express such rules no longer exists in
  X.Org 21; there is no `-sp` option and no mention of it in the tree.
- What untrusted mode *does* enforce is `SecurityTrustedExtensions[]`, an
  allowlist of two: `XC-MISC` and `BIG-REQUESTS`. That blocks XTEST and RECORD
  — and also RENDER, which is why untrusted sessions lose cursor themes.

So the useful half is missing and the enforced half is too blunt. This proxy
implements the policy the extension does not.

## Install

The proxy runs on the machine with the real X server. Nothing is installed on
the remote host.

```bash
scp remote:/path/xfilter.py remote:/path/xfilter_core.py ~/bin/
chmod +x ~/bin/xfilter.py
```

Both files must sit in the same directory; only `xfilter.py` is a command.

There is nothing to install with pip — the proxy is Python 3 standard library
only. It shells out to two system tools, and the prompt needs one more:

```bash
sudo apt install xauth xclip        # xauth: cookies;  xclip: the prompt's preview
sudo apt install python3-gi gir1.2-gtk-3.0    # only for --gate ask
```

`--gate ask` also needs somewhere to *show* the prompt, which is the part a
package cannot supply: the dialog opens on your real display (`--upstream`),
deliberately not on the filtered one, since routing it through the proxy would
put the dialog's own clipboard reads in front of the gate it exists to serve.
On a headless machine there is nowhere to draw it, whatever is installed. The
bindings are checked as soon as the arguments are parsed, so a missing package
is an immediate error rather than a failure after the proxy is already running.

## Use

```bash
# an interactive remote shell: everything launched from it is filtered
xfilter.py --gate ask --ssh remotehost

# or one application
xfilter.py --gate ask --ssh remotehost -- firefox

# any local command works too
xfilter.py -- xterm
```

It picks the first free display from `:20`, mints a private cookie in a temp
file, and runs the command with `DISPLAY` and `XAUTHORITY` already set. When
the command exits — or on Ctrl-C — it prints a report and cleans up.

To drive it by hand instead, start it without a command and use the two export
lines it prints.

| flag | effect |
| --- | --- |
| `--gate deny` | refuse clipboard reads silently (default) |
| `--gate ask` | hold the request and prompt, showing the value and which application asked |
| `--gate allow` | let clipboard reads through |
| `--dry-run` | report what the policy *would* do, blocking nothing — use it to measure a new application first |
| `--ssh HOST` | shorthand for `ssh -X -o ForwardX11Trusted=yes HOST` |
| `--log FILE` | also append the operation log (each new operation, and the exit report) to `FILE` |
| `-v` | log every connection and its outcome |

Trusted forwarding is required: `ForwardX11Trusted no` makes ssh run
`xauth generate` against the proxy, which cannot answer it. The proxy is the
boundary now, so trusted forwarding into it is the correct configuration.

## What it enforces

| From a filtered application | Result |
| --- | --- |
| Read `CLIPBOARD` / `PRIMARY` / `SECONDARY` | gated — refused, put to you, or allowed (matched by atom **id**, so a hardcoded id cannot skip the gate) |
| Convert a selection into **another** application's window | refused — the requestor field says where the owner writes its answer, so naming somebody else's window has a trusted application write there for you |
| Any rule that names an atom or an extension | the proxy resolves those names against your server at startup, so a client cannot dodge a rule by using an id or an opcode without ever asking what it is called |
| **Become** the owner of one of those selections | gated the same way — taking the clipboard clobbers your real copy and answers every later paste |
| Paste *out* into a desktop application | follows the same gate: it *is* taking ownership, so `--gate deny` refuses it and `--gate ask` prompts for it |
| Screen capture — `GetImage`, **or a RENDER `CreatePicture` of a foreign drawable** | refused |
| Covering the screen with borderless windows — one of them, several that add up to it, or one on your second monitor | gated by `--gate`, so a fake desktop or login prompt cannot be painted over yours |
| Keystroke logging — **XInput** raw/key/button/motion selection or device grab on a foreign window | refused |
| Keystroke logging — **`QueryKeymap`** polling (the global key-down bitmap) | answered as "no keys down" |
| Keystroke logging — **grabbing the keyboard**, even on the application's own window, by the core request or through XInput2 | the grab is allowed, because menus need it, but a key event reaches the application only while one of its own windows holds the focus — so a grab captures nothing you type elsewhere |
| Pointer tracking — **grabbing the pointer**, which reports every motion in the session | allowed (drag-and-drop needs it), but the position in those events is blanked wherever the pointer is not over the application's own window |
| Pointer tracking — **`QueryPointer`** / **`XIQueryPointer`** anywhere but over one of the application's own mapped windows | position blanked, input-state mask always blanked. `QueryPointer(root)` — the usual way to ask where the mouse is — answers (0,0) |
| XTEST, RECORD, MIT-SHM, Composite, DAMAGE, GLX, … | hidden and refused by opcode |
| Core grabs and input-event masks on foreign windows | refused |
| Watching or redirecting a foreign window's **children** — `SubstructureNotify` / `SubstructureRedirect`, including on the root | refused — the first is window enumeration by event rather than by request, the second makes the client your window manager |
| Watching a foreign window's focus (`FocusChange`) | refused — a client watches focus on its own windows |
| `PropertyNotify` for a property on a foreign window the client may **not read** | withheld — otherwise it learns that a title changed on a window it cannot see, and when; the allowed properties (theming, window management) still notify |
| `KeymapNotify` — the global key-down bitmap, pushed after every focus change | answered as "no keys down", like `QueryKeymap` |
| `GetInputFocus` naming a foreign window | answered as no focus — a client is still told truthfully when it holds the focus itself |
| The shared keyboard's **modifier and lock state** — `XkbGetState`, `XkbGetIndicatorState`, `XkbGetNamedIndicator`, `XkbGetDeviceInfo`, `GetKeyboardControl`'s LED mask, XInput `GetFeedbackControl` | blanked in every one of them — each change in it is a key the user pressed. The XKB events that push the same state are dropped; `XkbNewKeyboardNotify` and `XkbMapNotify`, which toolkits need, still arrive |
| **Who owns** `CLIPBOARD` / `PRIMARY` / `SECONDARY` — `GetSelectionOwner`, or the XFIXES monitor of it | the monitor is refused, and the poll answers a stand-in when somebody else holds it: polled, it is a trace of every copy and mouse-selection on your desktop. A client is still told truthfully that it owns a selection itself |
| Destroy, unmap, move, restack or reparent a **foreign** window | refused — allowed on the client's own tree |
| Create a window *inside* a foreign window | refused — an overlay clipped to a trusted window, without reparenting anything (a **root** parent is the ordinary case and allowed) |
| **Draw into** a foreign window — `PutImage`, `ImageText8`, `PolyLine`, `CopyArea`'s destination, … | refused — painting inside a trusted window's frame is the raw material of a spoofed prompt |
| Free or rewrite a foreign resource — `FreeGC`, `FreePixmap`, `FreeColormap`, `ChangeGC`, … | refused — X checks no ownership on any of these |
| Change a foreign window's background, border, colormap or **cursor** | refused — those are attributes of the window, so they change what its real owner displays |
| `SetFontPath` (server-global; emptying it breaks font loading for everyone) | refused |
| EWMH `_NET_CLOSE_WINDOW` / `_NET_ACTIVE_WINDOW` / … naming a foreign window | refused — the window the message *acts on* is checked, not just its type |
| Remap the keyboard through **XKEYBOARD** (`XkbSetMap`, `XkbSetControls`, `XkbGetKbdByName`, …) | refused — the extension route around the core remap rules |
| Reconfigure the shared screen through **RANDR** (resolution, rotation, gamma, primary output) | refused — reads pass, writes do not |
| Reshape a foreign window through **SHAPE** or XFIXES `SetWindowShapeRegion` | refused |
| Read the shared cursor — XFIXES `GetCursorImage`, or watch it change | answered as a blank 1×1 cursor; the change monitor is refused |
| `GrabServer` (would freeze every client, input included) | refused |
| Screensaver control (`SetScreenSaver`, `ForceScreenSaver`) | refused — a remote app can't suppress your auto-lock |
| Keyboard / pointer / modifier remapping; focus theft; pointer warps into foreign windows | refused, or scoped to the client's own windows |
| Read `WM_NAME`, `WM_CLASS`, `WM_COMMAND`, … | refused |
| Read a foreign window's geometry or attributes | answered with an empty window — the client is not blocked, it is told nothing |
| `TranslateCoordinates` naming a foreign window | answered as off-screen; root-to-root (drag and drop) and own-to-root (menus) still work |
| `CreateGC` / `CreatePixmap` / `QueryBestSize` against a foreign drawable | refused; against a **root**, which is the ordinary idiom, allowed |
| Read `RESOURCE_MANAGER`, `_XSETTINGS_SETTINGS`, `_NET_*` | allowed — theming and window management |
| EWMH client messages to the root window | allowed, unless they name a foreign window |
| `QueryTree` on a foreign window | answered as an empty tree — other clients' windows are not enumerable |
| An extension on neither list (`X-Resource`, `MIT-SCREEN-SAVER`, …) | reported **absent**, so the client takes its "no such extension" path |
| RENDER, XFIXES, XInput, SHAPE, XKEYBOARD, RANDR | allowed for drawing and devices, with their **arguments** inspected, not just their opcode |

An opcode allowlist is too coarse for the extensions that can reach the same
capabilities the core protocol is filtered for: RENDER can composite the screen
into a pixmap the client owns, XInput can deliver every keystroke, and XKEYBOARD
can remap the keyboard past the core rules that forbid exactly that. So each of
them gets a second policy layer keyed on its minor opcodes — the same argument
inspection the core protocol gets.

Each of the six names the minor opcodes it **allows** and refuses the rest, so
an extension request nobody has looked at is blocked exactly as an unknown core
request is. On top of that allowlist, the requests that reach a guarded
capability get their arguments checked: `CreatePicture` on a foreign drawable,
`XISelectEvents` and the device grabs, selection and cursor snooping, reshaping
or compositing into somebody else's window. The lists differ in width — XKEYBOARD
and RANDR admit only their queries, because their write surface *is* the
capability, while RENDER and XInput admit nearly everything the protocol
defines, because that is what drawing and input need. Over-blocking is caught by
`e2e.sh` and named in the log.

## Default deny, and the operation log

The policy is an **allowlist**, and this is the load-bearing property of the
whole design. Precisely:

- **The core protocol is default-deny.** A request is passed only if it is on
  `SAFE_CORE` or a rule in `judge()` rules on it. Anything else is blocked and
  logged.
- **Extension selection is default-deny.** An extension not on
  `ALLOWED_EXTENSIONS` is blocked, and reported *absent* to the client so it
  never asks.
- **Every inspected extension is default-deny inside the extension.** RENDER,
  XFIXES, XInput, XKEYBOARD, RANDR and SHAPE each allowlist their minor
  opcodes; an unrecognised one — a future protocol addition, or one nobody
  profiled — is refused, not forwarded.
- **A request the policy cannot parse is blocked**, not passed. A body too
  short for a field a rule reads means the policy does not know what the
  request does, which is the reason to refuse it rather than a reason to trust
  it. It is logged under its own reason, so it is distinguishable from a
  deliberate allow.
There is no remaining path by which a request the policy does not recognise
reaches the server. The allowlists for the drawing extensions are *wide* —
RENDER and XInput really are how modern toolkits draw text and handle input,
so nearly every defined request is on them — but wide is not the same as open:
the point is that "unknown" resolves to "refused".

Everything, allowed or blocked, goes through the operation log. That is what
turns "a request type nobody thought of is a gap" from a silent hole into a
visible, reviewable event.

The proxy logs each distinct operation the first time it sees it — the name, the
policy's verdict, and the process behind it. "Distinct" includes the verdict:
nearly every windowed request is allowed on the client's own window and refused
on a foreign one, so keying on the name alone would report whichever came first
and hide the other. An over-block sitting behind an earlier allow of the same
request is precisely the event this log exists to surface, so both lines appear,
and the exit report marks a name that shows up in each:

```
new operation: RENDER:Composite                    allowed  code (pid 4242) [local pid 1990, uid 1000]
new operation: SomeExt:7                            blocked  code (pid 4242) [local pid 1990, uid 1000]
```

Withheld **events** are named the same way, as `event:PropertyNotify` and the
like. They are worth calling out separately because they are the failure a
person actually meets: a refused request comes back to the application as an X
error, but there is no reply behind an event, so withholding one makes an
application quietly wait rather than fail. That is the difference between a
paste that reports a problem and a paste that simply never finishes, and until
the twenty-sixth pass those drops were the one thing the log did not record.

```
new operation: event:PropertyNotify                 blocked  code (pid 4242) [local pid 1990, uid 1000]
```

`--dry-run` reports these too. It withholds nothing — the client's stream is
byte-for-byte an unfiltered one — but it still works out which events enforcing
would take away and names them, so the ratchet below covers events as well as
requests. That is worth more than it sounds: an enforcing run tends to report
*fewer* refusals, because the first withheld event stops the application before
it reaches the next thing the policy would have refused.

The name is the application's own claim about itself and can say anything; the
`[local pid …, uid …]` is what the kernel reports for the connecting process and
cannot be forged. Logging goes to stderr, and to `--log FILE` as well; the exit
report lists every operation allowed and every one blocked. There are **no
per-request counters** — knowing an operation *appeared* is what maintaining the
allowlist needs, so the hot path stays a single set-membership test on a cheap
`(operation, verdict)` key.

The workflow is a ratchet: run a new application under `--dry-run` (nothing is
blocked, everything is logged), read what it needs, add the genuine needs to the
allowlist, then enforce. After that the log only shows what is new, and each
line is a deliberate "allow it or leave it blocked" decision.

## Tuning the policy

The lists at the top of `xfilter.py`: `SAFE_CORE` (core requests allowed as-is),
`ALLOWED_EXTENSIONS`, `DENIED_EXTENSIONS`, `FOREIGN_PROPERTY_ALLOW`,
`EWMH_MESSAGES`, `EWMH_WINDOW_TARGETS`, `GATED_SELECTIONS`,
`WINDOW_WRITE_REQUESTS`, `FOREIGN_RESOURCE_REQUESTS`,
`SCREEN_REFERENCE_REQUESTS`, `CURSOR_SOURCE_REQUESTS`, `CW_PER_CLIENT`,
`DENY_QUERYTREE`, and the per-extension minor-opcode sets
`XKB_ALLOWED`, `RANDR_ALLOWED`, `SHAPE_WINDOW_WRITES`. `SAFE_CORE`,
`WINDOW_WRITE_REQUESTS` and `ALLOWED_EXTENSIONS` are written as
request/extension **names**, resolved to opcodes once at startup. An extension
must appear in exactly one of the allow and deny lists; naming it in both is a
startup error rather than a contradiction settled by evaluation order.

**No command-line flag turns a rule off.** Anything deciding how strict the
policy is lives in these tables, so relaxing one is an edit that shows up in a
diff and in review, not an argument someone can add to a command line.

`--gate` is not an exception to that, because it is not a security switch: the
gate is always present and always consulted, and the flag chooses which answer
it gives. What it grants or withholds is a *capability the user decides to give
their own application* — and the forwarded application cannot set flags, so
this is the user choosing for themselves, not an attacker weakening anything.
It is safe by default (`deny`) and every other setting is explicit.

`--dry-run` is the one wholesale off switch. It is a mode rather than a partial
weakening — the profiling half of the documented workflow — it defaults to off,
and every line of its output says so.

The intended way to change them is to measure rather than guess. Run with
`--dry-run`, use the application normally, and read the *blocked* list at the end
of the report (or the live `--log`); add whatever it names that the application
actually needs. `e2e.sh` runs a set of clients through the enforcing proxy and
fails if the policy breaks any, so a too-tight allowlist is caught automatically.
That is how the shipped defaults were derived — from two
sessions totalling about 600,000 requests.

## One process shape

The accept loop always runs on its own thread and the main thread waits for
something that never finishes, whichever gate mode is in use. Under
`--gate ask` that wait is GTK's main loop, which insists on owning the main
thread and is what pumps the prompt queue; otherwise there is nothing to draw
and the main thread simply waits on the accept loop. Serving starts first
either way, so a display that is slow to answer cannot hold up accepting
clients — and the process does not have one structure for prompting and a
different one for everything else.

## How refusal works

A request cannot simply be dropped: the server counts requests to generate
sequence numbers, so swallowing one desynchronises every later reply.

- A request expecting no reply is replaced by `NoOperation`.
- A request expecting a reply is replaced by `GetInputFocus`, and its reply is
  swapped for the policy's answer when it arrives — using the real reply as a
  barrier keeps the substitution correctly ordered.
- Substituted answers are ones applications already handle: a property that
  does not exist, a window with no children, a grab already taken, a blank 1×1
  cursor. Errors are a last resort, since Xlib's default error handler exits
  the process.
- **Extension requests need this care too.** Every extension request has a
  major opcode of 128 or more, so the core `REPLY_REQUESTS` table cannot say
  whether one expects a reply. Each extension inspector names the reply-bearing
  requests it refuses, and an extension that is not on the allowlist at all is
  reported *absent* by `QueryExtension`, so a client never sends a request into
  it and never waits for a reply that will not come.
- A gated selection is refused by rewriting its atom to one nobody owns, so the
  *server* generates the standard "no owner" answer and the owning application
  never learns a paste was attempted. The `SelectionNotify` is patched on the
  way back so the client sees a refusal for the selection it asked about.

## Limits

- **The filtered client must have no other route to your server.** This is a
  precondition, not a caveat. A *local* process running as your own uid ignores
  the proxy completely: it opens `/tmp/.X11-unix/X0` and reads the real cookie
  out of `~/.Xauthority`, both of which its uid already grants. Nothing forces
  it through the filter, so pointing this at a local untrusted application
  defeats it in one line — architecturally, not through any bug that could be
  patched. It is meaningful for **remote forwarding**, where the client is
  genuinely confined to the tunnel and has neither a local socket nor a cookie
  for `:0`. Anything connecting to `:0` directly is untouched, including any
  other `ssh -X` session you have open.
- **Everything behind one proxy is one trust domain.** A forwarded application
  can read and capture *another forwarded application's* windows: through the
  same proxy, `GetImage` on a sibling's window hands back its pixels, its title
  reads back, and a property written into it lands — while the same requests
  from the same client against one of your **local** applications return nothing
  and do not land (measured, twenty-ninth pass). This is deliberate, not an
  oversight: the proxy cannot tell which connections belong to which program. An
  application may open nine, so treating each connection as its own domain would
  make an application a stranger to its own windows; and over a single `ssh -X`
  tunnel every forwarded program shares the tunnel's pid, so process credentials
  cannot separate them either. It matters because the obvious way to run the
  tool puts several programs inside the boundary — `--ssh remotehost` filters
  *everything* launched from that shell, so your editor and a tool you only
  half-trust can reach each other. **If two forwarded programs should not be
  able to read each other, give them one proxy each**, which is what the
  single-application form already does:

  ```bash
  xfilter.py --gate ask --ssh remotehost -- firefox
  ```
- Completeness is the rule table, not the server. A request type nobody
  considered is now **blocked and logged** by default rather than passed — which
  is what the default-deny allowlist and the operation log are for. The argument
  inspection for RENDER, XFIXES and XInput covers the demonstrated capture and
  input vectors, not every request those extensions define; a request the
  allowlist admits into one of the six inspected extensions is passed on the
  strength of being on that list; only the requests that reach a guarded
  capability have their arguments checked as well.
- **Keyboard state is closed, in both directions.** This entry used to read
  "XKEYBOARD state is readable", on the reasoning that closing it would mean
  filtering the *event* stream and the proxy did not. It does now.
  `XkbGetState` is answered with its modifier and group fields blanked, and the
  keyboard's *lock* state — the indicators — is blanked in every request that
  answers it (`XkbGetIndicatorState`, `XkbGetNamedIndicator`,
  `XkbGetDeviceInfo`, core `GetKeyboardControl`, XInput `GetFeedbackControl`).
  On the event side, `XkbSelectEvents` stays allowed because toolkits need
  `XkbNewKeyboardNotify` and `XkbMapNotify`, and those two are exactly what the
  event filter passes: every other XKB event, the state and indicator
  notifications included, is dropped on the way out. The cost is that a
  forwarded application cannot show you a Caps Lock or keyboard-layout
  indicator.
- **Window enumeration is closed**, in both the request and the event stream.
  `QueryTree` on another client's window answers an empty tree, the `child`
  field `TranslateCoordinates` returns is blanked, and selecting
  `SubstructureNotify` on the root — which would otherwise push a
  create/destroy/move feed for every top-level window, and is the better route
  of the two — is refused, as is `SubstructureRedirect`, which would make the
  client your window manager. Measured with a real window on the upstream server, the filtered
  client sees an empty list where it used to see
  `0x200003 (has no name) 0x0+0+0`. Reading the screen size from the root — what
  ordinary clients want the root for — is unaffected, and a client still reads
  its *own* tree, which is how it finds the frame the window manager reparented
  it into.
- **Drag-and-drop *out* of a filtered application does not work.** Its payload
  travels through a selection (`XdndSelection`) like a paste, and that half
  would be fine — but to find a drop target the source has to read `XdndAware`
  on another client's window, and foreign property reads are refused. Dropping
  *into* a forwarded window is unaffected. Adding `XdndAware` to
  `FOREIGN_PROPERTY_ALLOW` and leaving `QueryTree` open would restore it, at
  the cost of the enumeration above.
- **Colormap arithmetic.** `AllocColor` and friends can name another client's
  colormap and in principle exhaust its cells. On the TrueColor visuals every
  modern session uses, colormaps are effectively read-only and this is close to
  meaningless, so it is noted rather than answered with six synthetic replies.
- **`QueryPointer` still returns the pointer position while it is genuinely
  over the forwarded application.** The reply always carries screen
  coordinates, and a client legitimately queries the pointer over its own
  windows (menus, drag and drop), so that case is left open: it is irreducible
  anyway, since the client can work the position out from its own window's
  origin. Everything else is blanked — the pointer while it is elsewhere on the
  desktop, a query naming a window the policy has no record of (the root
  included), and one naming a window the client created but never mapped.
  `GetMotionEvents`, the pointer-motion history, is refused outright.
- **The extension write rules can over-block.** A forwarded application that
  legitimately wants to set the screen layout (a presentation tool calling
  RANDR) or load its own keymap is refused along with one abusing them. The
  operation log names what was blocked, so the trade is visible and reversible
  by editing `RANDR_ALLOWED` / `XKB_ALLOWED`.
- **Screensaver refusal can over-block.** A forwarded media player that resets
  the screensaver to prevent blanking is refused along with an application
  trying to keep your session from locking; the safe default was chosen.
- **The display is cookie-protected by default.** Every run mints a private
  cookie in a temp file and removes it on exit, whether or not a command is
  spawned; `--auth FILE` only says where to put it. The two export lines
  printed on startup carry it to a shell you drive by hand. A local user
  without that cookie cannot reach the display around the filter.
- **A forwarded application cannot register a session-wide hotkey.** A global
  shortcut is `GrabKey` on the **root** window, which intercepts that key
  combination for every application on your display, not just the one asking —
  a keylogger for that combination, and a theft of your desktop's own binding.
  It is refused, and the log names it (`core:GrabKey blocked`). In-application
  shortcuts are unaffected: those are ordinary key events to the application's
  own window and never touch `GrabKey`. Measured with `terminator`, which asks
  for one on startup, renders and works normally without it.
- **Two *forwarded* applications cannot pass the clipboard between themselves
  under `--gate deny` either.** There is only one `CLIPBOARD`, and it lives on
  your real server — the proxy forwards to it. So "take the clipboard so my
  sibling application can paste it" is byte-for-byte the same request as "take
  the clipboard so the next thing you paste anywhere is mine". Nothing in the
  protocol separates them, so the safe default refuses both. `--gate ask` gives
  you copy and paste between forwarded applications, at one prompt per
  connection per `--gate-remember` window.
- **`--gate deny` also disables copying *out* of the forwarded application.**
  Offering a copy means becoming the owner of `CLIPBOARD`, and at the protocol
  level that is indistinguishable from an application seizing the clipboard to
  clobber your copy and answer every later paste with text of its choosing.
  There is no way to tell the two apart from the request, so the safe default
  refuses both. **`--gate ask` is the setting that gives you working copy-out**,
  by putting the decision in front of you; `allow` gives it without asking.
  The first time the gate refuses under `deny`, the log says so and names the
  setting — a blocked clipboard otherwise reads as a defect rather than a
  choice.
- **If the proxy loses sight of the focus, a client holding a keyboard grab
  goes deaf rather than getting everything.** A grab is allowed — menus need one
  — and what keeps it from being a keylogger is that keystrokes reach the client
  only while one of its own windows has the focus. That question is asked on the
  proxy's own connection to the server; if that connection dies, the answer is
  "I don't know", and the safe reading of "I don't know" for a client holding
  the keyboard is to withhold. A client *without* a grab keeps its keys, because
  X was only ever sending it its own. The log says when this happens, so a menu
  that stops taking arrow keys has a findable cause.
- **A permitted paste can be any size, but its far end must keep taking it.**
  A payload bigger than one request crosses by the INCR protocol, chunk by chunk
  into the receiving application's window, and the permission the gate granted
  is what lets each chunk through. That permission is refreshed every time the
  receiver takes another chunk, so a large or slow paste runs as long as it
  needs to — 19 MB at five seconds a chunk is measured. What it will not survive
  is the receiver going quiet for over a minute mid-transfer: the grant lapses,
  and because X gives an event no way to fail, the paste hangs rather than
  errors. The log names the withheld event when it happens.
- **The prompt's grant is per connection, not per application.** Keying a
  remembered *Allow for a while* on the connection is what stops a second
  application inheriting a grant by claiming a name already allowed. The cost
  is that an application which opens many connections may be prompted more than
  once. The dialog shows the claimed name (which the client controls, marked
  *self-reported*) alongside the connecting process's real pid and uid. Over a
  single `ssh -X` tunnel every forwarded application shares that pid, so the
  credentials distinguish local clients but not two remote applications on the
  same tunnel — the per-connection token still keeps their grants separate.
- The relay is Python. It handled 435,000 requests in a session
  comfortably, but it copies every message.

## Tests

```bash
python3 test_unit.py        # unit: policy + wire parsing, no X server needed
./e2e.sh                    # end-to-end: real clients through the enforcing proxy
./attack.sh                 # adversarial: the attacks, direct and through the proxy
./attack.sh --dry-run       # the suite's own self-test: the checks must go red
RIG_SERVER=xephyr RIG_WM=both ./attack.sh   # ...and against other rigs
RIG_PARENT="$DISPLAY" RIG_SERVER=xephyr ./attack.sh   # ...watching it happen
```

`e2e.sh` also checks two things beyond rendering: for the clients named in
`RIG_MENU_APPS` it opens a context menu, and then presses a key in it. Opening
one takes a grab and navigating one takes the keys that grab delivers, which
makes them the interactions a policy change is most likely to break — a change
that stopped GTK menus opening once went unnoticed here, because watching a
window appear and stay up is not the same as watching it work. The keyboard half
measures the screen's own noise floor first and dumps the menu window rather
than the root, since a compositing window manager stops the root changing at
all.

The **attack** suite is the other half of `e2e.sh`: where that one asks whether
the policy breaks real clients, this asks whether the attacks it claims to stop
still fail. Each of its checks runs the same attack twice — straight at
the server, where it **must** succeed, and through the proxy, where it must not.
A check whose direct run fails is reported `INCONCLUSIVE` rather than passed,
because an attack that has quietly stopped working proves nothing about the
policy. Run it with `--dry-run` and the policy enforces nothing, so nearly every
check must go red: a suite that cannot fail is decoration.

How near "nearly" is depends on the rig, and the self-test says which rather
than leaving you a number to interpret: it prints the count that went red and
then **names** every check that did not, because a check that cannot go red with
the policy switched off is not evidence about the policy. One check stays green
by design (sanitising the proxy's own log output is not a policy decision, so it
holds in either mode). Two more are rig-dependent — `CopyArea` cannot be mounted
under a compositing window manager, and the pointer-grab trace cannot be mounted
under Xephyr — so the expected tally is 28 of 29 on `xvfb + openbox`, and 27, 27
and 26 on the other three.

Both harnesses read the **same** rig variables, so one environment drives either
and the command is the only thing that changes:

| variable | values |
| --- | --- |
| `RIG_SERVER` | `xvfb` (default), `xephyr`, `both` |
| `RIG_WM` | `openbox` (default), `metacity`, `none`, `both` |
| `RIG_COMPOSITE` | `0` to run metacity without its compositor |
| `RIG_PARENT` | a display to nest Xephyr in — `"$DISPLAY"` to watch it |
| `RIG_DWELL` | `e2e.sh` only: seconds to watch each client (5) |
| `RIG_MENU_APPS` | `e2e.sh` only: clients whose context menu must open *and* answer the keyboard (`gedit`) |
| `RIG_MENU_KEY` | `e2e.sh` only: the key that menu must respond to (`Down`) |

Which server you pick decides what can be tested at all: Xvfb offers a thin
extension set, while Xephyr is Xorg-derived and hands a client the Composite,
DAMAGE, MIT-SHM, RECORD and XTEST surface a real desktop does — and an attack is
only proven closed on a server that offers the route it would take. Xephyr draws
into a window, so without `RIG_PARENT` it is nested in a headless Xvfb and the
run stays unattended; the parent is only a canvas, and the nested server still
offers its clients the full extension set either way. (`e2e.sh` also still
accepts its older `E2E_*` names.)

The **unit** tests (129) build request bytes by hand and ask `judge()` what it
thinks — no X server, no network, no GUI — which is where a wrong answer is a
security hole rather than a crash. They cover the parts that must not drift: the
BIG-REQUESTS framing that keeps a request from being smuggled past the policy,
the clipboard gate matched by atom id (reading it *and* taking it), the RENDER,
XInput, XKEYBOARD, RANDR, SHAPE and XFIXES argument checks, the foreign-resource
gate on the requests that *modify* a window, draw into one, free or rewrite
another client's graphics context, or ask the window manager to act on a
window, the fail-closed handling of a request the policy cannot parse, the root-window
exception that keeps menus and drag-and-drop working while foreign windows stay
opaque, the per-connection keying of the prompt, the polling
keyloggers (`QueryKeymap`) and trackers (`QueryPointer`), the pointer-mask
scrub, the identity parsing behind the operation log, and the default-deny
fall-through.

The **e2e** test stands up a throwaway server and window manager, runs the
enforcing proxy in front, launches a set of X clients through it
(`xeyes`/`xclock`/… by default; pass your own, or list heavy local apps in a
gitignored `e2e.local`), and fails if the default-deny policy breaks any of
them — so the allowlist can only be tightened deliberately.

What a toolkit asks the server for depends on the environment around it, so
two axes of that environment are selectable. Each defaults to the cheap
setting, and `both` runs the same clients once per value:

| variable | default | other values |
| --- | --- | --- |
| `E2E_SERVER` | `xvfb` — headless frame buffer | `xephyr`, a genuine Xorg-derived server whose visuals, RENDER and Composite are the ones a desktop client meets; `both` |
| `E2E_WM` | `openbox` — reparenting, no compositor | `metacity`, reparenting **and** compositing, as a desktop session is; `none`; `both` |
| `E2E_DWELL` | `5` seconds | how long a client is watched after it maps |
| `E2E_COMPOSITE` | `1` | `0` runs metacity without its compositor |
| `E2E_PARENT` | a private `Xvfb` | a display to nest `Xephyr` in, e.g. `"$DISPLAY"`, so you can watch |

The axes matter because a reparenting window manager wraps each client in a
frame the client does not own, and a compositor redirects those frames — both
change which requests a toolkit sends about windows it did not create, which is
exactly the surface this policy substitutes replies for.

A client also has to *stay up* to pass, not just map a window: it is watched
for `E2E_DWELL` seconds after its first window appears, because a substituted
reply can be malformed in a way the toolkit only trips over later — a reply
field that resolves to a NULL pointer inside Xlib, say, which is a real bug
this test once scored as a pass. Exit status distinguishes the two things that
can go wrong: `1` means the policy broke a client, `2` means the rig itself
would not start and the run says nothing about the policy. Needs `xwininfo`,
`xauth` and `Xvfb` or `Xephyr`; skips absent apps.

## License

MIT. See `LICENSE`.

## Files

- `xfilter.py` — the command: policy, gate, spawning, reporting.
- `test_unit.py` — the policy and parsing tests.
- `e2e.sh` — end-to-end test: real X clients through the enforcing proxy.
- `attack.sh`, `attack.py` — adversarial test: the attacks the policy claims to
  stop, each run straight at the server and through the proxy.
- `xfilter_core.py` — the relay: connection setup and cookie swap, request and
  reply parsing, atom and extension bookkeeping, the profile. Also runs
  standalone as a pure profiler (`python3 xfilter_core.py --display :20 …`),
  which is how the policy was derived.
