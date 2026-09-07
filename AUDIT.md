# Security status — xfilter

One audit, run in twenty-nine passes between 27 August and 6 September 2026.
This document is the **current state**: what the audit closed, what it left
open, and what the whole thing is worth. Findings that are fixed are removed —
the code, its tests and the git history are their record.

`xfilter` is a filtering X11 proxy. A forwarded application talks to it instead
of to the display, it talks to the real display server, and every request,
reply and event that passes through is judged against a policy. It
re-implements, in the protocol stream, restrictions the X SECURITY extension was
supposed to enforce and does not.

## The words this document keeps using

X11 is a client/server protocol: applications (**clients**) send **requests** to
the display **server**, get **replies** back, and are pushed **events**. The
problem this project exists for is that the protocol was designed with no
isolation between clients — by default any client can read any other client's
window, keystrokes and clipboard.

- **root window** — the desktop-background window that contains all the others.
  A permission granted "on the root" is a permission over the whole screen.
- **own vs. foreign** — a window the filtered application created, versus one
  belonging to somebody else. Almost every rule in the policy turns on this.
- **property** — a named value attached to a window: its title (`WM_NAME`), the
  desktop-manager conventions (the `_NET_*` names), and so on.
- **atom** — a small number the server hands out to stand for a string, so
  properties and clipboards are named by number once they are on the wire.
- **selection** — X's clipboard. `CLIPBOARD` and `PRIMARY` are selections, each
  owned by one client at a time; a paste is a negotiated transfer between two
  clients, chunked for large payloads by a convention called INCR.
- **grab** — a client asking the server to route *all* keyboard or pointer input
  to it, whatever the user is doing. Opening a menu needs one; so does a
  keylogger.
- **override-redirect** — a flag telling the window manager to keep its hands
  off a window: no frame, no placement, no rules. Menus and tooltips use it; so
  would a fake full-screen desktop.
- **extension** — an optional protocol module (RENDER, XKEYBOARD, XInput, …),
  each with its own numbered sub-requests.
- **`--gate`** — the proxy's one user-facing control, in three settings: `deny`
  (the default), `ask` (prompt the user), `allow`. It governs the clipboard and
  the full-screen/spoofing routes.
- **the test setups** — `Xvfb` is a display server with no screen attached;
  `Xephyr` is a display server that draws inside a window of another one, which
  is how a whole desktop gets run and driven without a monitor; `openbox` and
  `metacity` are two window managers that behave differently enough to matter
  (metacity composites). Every test runs against each combination.

---

## Status

| | |
|---|---|
| **Unresolved findings** | **none** |
| Accepted residuals | 21 — the tables below are the honest inventory |
| Unit tests | 144 |
| Attack suite | `./attack.sh` — 29 attacks, each verified to work **directly** against an unprotected display and to fail **through the proxy**, on `{Xvfb, Xephyr} × {openbox, metacity}` |
| Suite self-test | `./attack.sh --dry-run` — pointed at a proxy that enforces nothing, 26–28 of the 29 must go red; the ones that stay green are named per setup, not averaged away |
| End-to-end | `./e2e.sh` green under both window managers, WebStorm included: windows appear, stay up, menus open, keys land in them, the clipboard moves in both directions |

An attack whose direct run does *not* succeed is reported `INCONCLUSIVE`, never
`PASS`. An attack that has quietly stopped working proves nothing about the
policy, and a green row for it would be a lie.

---

## What the audit fixed

| Area | Was | Is now |
|---|---|---|
| **Screen capture** | A forwarded application could ask the server for the pixels of the whole desktop or of any other application's window — through the screenshot request (`GetImage`), the copy request (`CopyArea`) or the compositing extension (RENDER) — and the extensions that move pixels through shared memory were available to it | Every route refused. The shared-memory and compositing extensions (MIT-SHM, Composite, DAMAGE, Present, DRI3, GLX) are denied and report themselves **absent** when asked, so a client falls back cleanly instead of hanging |
| **Keylogging** | Five separate ways to read keystrokes meant for other windows: raw input events (XInput), asking for key events on the root window, polling the keyboard bitmap (`QueryKeymap`), the key state pushed on every focus change (`KeymapNotify`) — and a **keyboard grab on the client's own window**, allowed from the start because grabbing is exactly what opening a menu does | All refused, or answered as though no key were pressed. The grab is still allowed, so menus still work, but a key event now reaches a client only while one of **its own** windows holds the keyboard focus |
| **Activity trace** | With pixels and keystrokes closed, a client could still follow the user around: which window is active, which modifier and lock keys are held, where the pointer is anywhere on screen, the list of every window on the desktop, and pointer enter/leave events on the root | Each one blanked or withheld. The lesson the audit kept relearning: a fact is closed only when **every name for it** is closed — one Caps Lock indicator was readable through six different requests and two different events |
| **Fail-open checks** | Several gates were written as "refuse these, allow everything else", so anything nobody had thought of passed. Fifteen-odd others silently skipped themselves when a request was too short to contain the field they were supposed to check | Inverted to "allow these, refuse everything else". A request that does not carry the field its gate reads is now refused, verified by replaying every gated request truncated at every possible length |
| **Extension surface** | Five extensions were trusted on their name alone, with none of their sub-requests inspected — and inside the others, a sub-request nobody had classified was allowed by default at the end of the checks | Every allowed extension lists the sub-requests it admits and inspects their arguments. Each admitted sub-request must be declared either *safe* (names nothing belonging to anyone else) or *gated* (checked), and the program refuses to start if one is left unclassified |
| **Names vs. numbers** | The rules are written in names ("the fullscreen property", "the keyboard-state events"); the protocol carries numbers; and the proxy learned the mapping by watching the client's own traffic. So a client that simply never asked for a name walked straight past the rule that depended on it | The proxy resolves its own vocabulary against the real server before any client connects, so no rule waits on the client it is judging to name something first |
| **"Which windows are ours"** | Tracked per connection, so an application's second connection did not know about the first's windows; windows it had no record of were treated as the client's own; and nothing was ever forgotten. Worse, when a filtered client disconnected the proxy kept claiming its range of ids — which the server hands out again — so a **trusted** application that inherited them could be read, captured and written through the proxy | One model per application, shared by all its connections, aware of which windows are actually on screen, and forgetting both what the server frees and what a departed client leaves behind |
| **Clipboard and pasting** | A paste is a transfer the proxy has to permit, and it did not check that the **destination** window belonged to the client asking — so a client could direct a trusted application to write into a third application's window. The permission it granted never expired; once it did, it expired in the middle of a large paste instead | A transfer lands only in the client's own window. The permission expires when a transfer goes idle and refreshes while it keeps moving, so long pastes finish. `--gate ask` is verified end to end, and the log records what the user actually chose instead of logging every prompt as "blocked" |
| **Desktop spoofing** | Nothing stopped an application painting a full-screen fake desktop or fake login prompt in its own window and reading what the user typed into it. Every individual step is legitimate, so no isolation rule applied | Gated by `--gate`, on both routes: the override-redirect flag is stripped so the window manager frames the window like any other, and the fullscreen request to the window manager is removed. Tiled windows' **total** area is counted, so four quarter-screen windows cannot add up to one, and each monitor is measured against itself |
| **The write direction** | Reading was never the only risk: a client could send forged keystrokes and clicks into another application's window, write properties into it, kill it, or open the display server to the whole network | All refused — including the two special destinations that mean "whatever window is under the pointer" and "whatever window has focus", which resolve to a trusted window |
| **The operation log** | A client picks its own window-class string, and that string went into the log unescaped — so it could write convincing lines of the security log itself | Escaped |
| **Testing** | Every finding was measured once, by hand, on the day it was found. Nothing ever re-ran those measurements | `attack.sh` re-runs 29 of them on every setup, `e2e.sh` opens a real menu and presses a key in it, and a nested Xephyr-inside-Xvfb desktop makes both runnable with no monitor attached |

---

## What is missing

Nothing unresolved. What follows is what the audit **accepted** — each one
measured, weighed, and left for a stated reason.

### Information a forwarded application can still get

| # | Still reachable | Why it stays |
|---|---|---|
| 1 | **Another forwarded application behind the same proxy.** Measured: it captured a sibling's pixels (4096 bytes of them), read that sibling's window title, and wrote a property into its window — while the same three requests aimed at a *trusted local* application returned nothing and did not land | Deliberate. The proxy decides "is this ours?" from the range of ids it has issued, because one application may open nine connections, and over a single `ssh -X` tunnel there is nothing — not even the process id — to tell two forwarded applications apart. So **everything behind one proxy is one trust domain.** The mitigation is to run one proxy per trust domain — `xfilter.py -- firefox` already is one, and `--shared --domain NAME` makes "one per account, reused by every shell into it" the automatic shape rather than the disciplined one |
| 2 | **Where the pointer is, while it is over the application's own windows** — by asking (`QueryPointer`) or through the motion and enter events on those windows | Irreducible: the application knows where its own window sits, so it can work the position out regardless. Everywhere else the position is blanked, so the trace across the rest of the desktop is gone. One residual: where another window is stacked on top of one of the client's own, a pointer over *that* window still reads as in-bounds |
| 3 | **Entering and leaving the application's own windows** reports the pointer's screen position and which modifier keys were held at that moment | Hover behaviour and tooltips need these events. They fire once per crossing rather than continuously, which makes them a far thinner channel than the same events on the root — those are refused |
| 4 | **The position and size of a window sitting on top of one of the client's own.** Reading back its own pixels is allowed (they are its own), and the server returns the covered region **blank** rather than the neighbour's content — but the shape of that blank rectangle is the neighbour's geometry. Measured: `246×185+120+80`, an xterm's position and size to the pixel | A silhouette, not content, and it needs the attacker's window manoeuvred underneath the target first. Suppressing it means tracking every foreign window stacked above every own window, which the proxy does not do — for a narrower leak than others already accepted |
| 5 | **Which applications are running, from the table of names.** Walking over a range of atom ids returns every string any client has interned this session — toolkit markers, application-private names — which fingerprints the desktop | Refusing it would break every client that resolves a name it was handed. And atoms are interned at startup and never change, so this is a fingerprint taken once, not a trace of what the user is doing |
| 6 | **Which virtual desktop the user is on, and when they switch** (`_NET_CURRENT_DESKTOP` on the root) | The client learns the same thing from its own window being hidden when the desktop changes, and *that* signal cannot be refused without breaking it. Closing this one buys latency, not isolation |
| 7 | **A fake dialog that does not fill the screen** — a convincing `sudo` prompt, say — is not stripped | Only the full-screen shapes are gated, those being the ones that can impersonate the entire desktop. The complete answer is spatial rather than policy: run the forwarded clients inside a framed `Xephyr` window they cannot paint outside of |
| 8 | **Drag-and-drop payloads are not gated** the way the clipboard is | That selection holds something only during a drag the user is physically performing with the mouse |
| 9 | **Colormap arithmetic** — a client can name another client's colour table and in principle exhaust it | Meaningless on the true-colour displays every modern session uses |

### What does not work as a result

| # | Cost | Why it is paid |
|---|---|---|
| 10 | **Dragging something *out* of a filtered application does not work** | To know whether the window under the pointer accepts a drop, the dragging application has to read a property on somebody else's window — a foreign read the policy refuses — and it needs the desktop-wide window listing the audit closed. Restoring drag-out means reopening both |
| 11 | **Under the default `--gate deny`, copying *out* of a filtered application does not work** | Offering a copy means claiming ownership of the clipboard, and that request is identical, at the protocol level, to one seizing the clipboard to feed you something else. `--gate ask` gives both directions |
| 12 | **There is one clipboard, shared even between two filtered applications** | The alternative — the proxy emulating a private clipboard among its own clients — was considered and **declined**: several hundred lines of clipboard-protocol emulation, chunked transfers included, to remove a prompt that `--gate ask` already handles at one prompt per connection |
| 13 | **The prompt's answer is remembered per connection, not per application** | Over a single `ssh -X` tunnel every forwarded application shares one process id; the credentials the proxy can see separate local clients from remote ones, but not two remote ones from each other |
| 14 | **A filtered application cannot claim a session-wide hotkey** | Correctly so: a key combination grabbed on the root is a keylogger for that combination. Confirmed against `terminator`, which asks for one and works fine without it |
| 15 | **The write rules over-block.** An application legitimately changing the screen layout, loading a keymap or resetting the screensaver is refused along with one abusing those | The log names what was blocked, so the trade is visible and reversible by editing the tables |
| 16 | **A paste whose far end goes quiet for sixty seconds stalls, and stalls silently** | Some time limit is the point: a permission that never expired would be a standing licence to write into another application's window. A transfer that keeps moving refreshes its own clock, so only a genuinely stuck one is affected — and a stuck paste is already broken. The cost is that the proxy turns a slow application into a hung one rather than an erroring one, because the protocol gives an event no way to fail. The log at least names the event it withheld |
| 17 | **A sub-request the proxy does not recognise, inside an extension it otherwise allows, is dropped rather than answered** — and a client waiting for the reply waits forever | Only reachable through a future addition to an extension. The log names it the first time it happens |
| 18 | **Latency.** The proxy is Python and copies every message. Measured at 435,000 requests in one session without trouble, but the JetBrains runtime benchmarks the connection at startup and prints *"Detected slow X11, switched off alpha compositing of images"*, turning off a rendering path by itself | Correct behaviour on its part, and a fair description of the proxy. `-Dremote.x11.workaround=false` forces the path back on, at a redraw cost |

### Where the coverage is thinner than the numbers suggest

| # | Gap | Note |
|---|---|---|
| 19 | **Two of the 29 attacks cannot be mounted on every test setup.** Copying from a window we do not own does not work under a compositing window manager, because windows are drawn off-screen and there is nothing on screen to copy; and the pointer-grab trace does not work under `Xephyr`, because the pointer is driven by the outer server rather than the nested one | Both still go red on the setups where the attack is possible, so each closure *is* tested — but running the suite on one setup proves slightly less than the list of checks suggests. The self-test names them per setup, which is what makes this visible rather than silent |
| 20 | **Two sub-requests are classified *safe* although they do name a resource** — RENDER's animated-cursor create and its gradient creates | Judged low-risk today, and they sit visibly in the "safe" list rather than being swallowed by an allow-everything tail; each is a one-line move to "gated" if that judgement changes. The start-up check proves every sub-request **has** a classification; only reading each reply proves it has the **right** one |
| 21 | **Blanking "which window has the focus" assumes the window manager focuses the application's own window** — measured true under both `openbox` and `metacity`, and the blanking is conditional, so "do I have the focus?" still answers correctly | Under a window manager that focuses a proxy window of its own instead, the symptom would be a forwarded application that draws but ignores the keyboard, and the fix is to drop that one rule |

---

## The three things that would each be fatal, and why none are

1. **Losing the thread of the protocol.** If the proxy ever lost track of where
   one request ends and the next begins, it would be reading garbage and
   enforcing nothing. Not possible in principle: every request carries its own
   length in its header, so the proxy finds the next one without understanding
   this one. The single ambiguous case — a zero-length header, which is legal
   only after a specific extension is enabled — is dropped rather than guessed.
2. **Data channels that go around the proxy** — the classic "you cannot filter
   X" argument. Six extensions can move pixels through shared memory or through
   file descriptors passed between processes, neither of which crosses the byte
   stream the proxy reads. Closed three ways at once: all six are denied; the
   proxy never accepts a passed file descriptor, so one would be dropped even if
   a request slipped through; and all six require the client to be on the same
   machine, which a forwarded remote client is not.
3. **A second route to the real display.** For a remote client, there is none:
   it has the forwarded connection, no credentials for the local display, and no
   filesystem on the local machine. The three requests that could change that —
   minting a fresh credential, and the two that open the display to the network
   — are denied.

## The boundary that does kill it — local programs running as you

The filter is **worthless against a local process running under the user's own
account.** That process ignores the proxy entirely: it opens the display
socket directly and reads the real credential out of the user's home directory,
both of which its own account already grants it. Nothing forces a local program
through the proxy.

So the project is meaningful **only** for remote forwarding, where the attacker
really is confined to the tunnel. Deployed to sandbox a *local* untrusted
application it is defeated in one line — architecturally, not through a bug that
could be patched. This is a precondition, not a caveat.

## What it therefore is

Hardening for remote-forwarded applications you *semi-trust*, not a containment
jail for ones you do not. X11 is shared-everything — one keyboard, one pointer,
one screen, one clipboard — so some leakage is irreducible without breaking
ordinary applications, and no policy makes `ssh -X` as safe as not forwarding at
all. Within that ceiling the reductions are real: X's own SECURITY extension
aimed at the same target and was abandoned for effort and client compatibility,
not because the goal was impossible. This is a "better `ssh -X`", which is a
legitimate thing to be — provided it is not sold as more.

Sources for the trusted-X framing:
- https://github.com/gravitational/teleport/blob/master/rfd/0051-x11-forwarding.md
- https://laurentschneider.com/wordpress/2015/06/untrusted-x11-forwarding.html

---

## What the closure claims rest on

Every attack below was run twice: once straight at an unprotected display, where
it **must** succeed, and once through the enforcing proxy, where it **must**
fail. The middle column is the point — each of these genuinely captures the
screen or the keystrokes when the proxy is not in the path, so the right-hand
column is the policy working rather than the attack failing to work.

| attack | straight at the display | through the proxy |
|---|---|---|
| screenshot the whole desktop | 3200 bytes of screen | refused |
| screenshot another application's window | the victim's pixels | refused |
| copy the screen into our own pixmap, read it back | copies | dropped |
| the same capture through the compositing extension | creates the handle | dropped |
| are the shared-memory / compositing extensions there? | yes | reported absent |
| ask for raw key events, then type elsewhere | leaked `s-e-c-r-e-t…` | nothing |
| ask for key events on the victim's window | leaked keycode 38 | nothing |
| ask for key events on the root window | selected | refused |
| poll the keyboard for what is held down | the real bitmap | all zero |
| grab the keyboard on our own window, then type elsewhere | leaked `s-e-c-r-e-t` | no key events while another window has focus |
| grab the pointer, then watch the desktop | traced it across the screen | delivered, positions blanked off its own windows |
| read the key state pushed on focus-in | carries the key | zeroed (248 bits → 0) |
| ask where the pointer is — via the root, an unmapped window, a second connection | the true screen position | blanked |
| go full-screen: override-redirect, window-manager request, four tiles, second monitor, two connections | a fake desktop | gated by `--gate` on every route |
| list every window on the desktop | every window id | refused |
| read another application's window title | the title | refused |
| aim a clipboard transfer into another application's window; mint the permission for it | lands | refused |
| forge a line of the operation log through our own window class | lands | escaped |

## What the testing does and does not prove

`./e2e.sh` proves the policy is permissive enough for the applications it runs,
in the environment it builds. It does not prove a real desktop session works:
early in the audit, three defects turned up on the user's own display and **none
of them reproduced in the harness**. Two changes came out of that and still
hold — an application has to *stay up* to pass, not merely put a window on
screen; and the environment is a variable rather than an assumption
(`E2E_SERVER`, `E2E_WM`, either of which takes `both`), with the exit status
separating a broken policy from a test setup that would not start.

A clean run is necessary and not sufficient. Java IDEs forwarded over `ssh -X`
to a real display are what have found every defect the harness missed.
