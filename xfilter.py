#! /usr/bin/python3
"""Policy-enforcing X11 proxy, built on the relay in xfilter_core.py.

Same position in the chain, same relay, but every request is now put to a
policy first.  The policy is enforced unless --dry-run is given, which
records and reports the decisions without refusing anything, so you can
see what a policy would do to a real application before letting it do it.

    ./xfilter.py --display :20 --auth ~/.Xauthority-filter --upstream :0
    ./xfilter.py ... --dry-run          # to look first, refusing nothing

The policy is default-deny: a request is passed only if it is on the safe
allowlist (SAFE_CORE / ALLOWED_EXTENSIONS) or a rule in judge() rules on
it -- reads of other clients' data are refused, the handful of foreign
reads theming and window management need are kept, CLIPBOARD and PRIMARY
are gated, and anything nobody thought of is blocked and logged rather
than passed on trust.

Requests are handled by one of a few strategies: allow (pass as-is), own
(allow on the client's own resource, refuse on a foreign one), gate (the
clipboard prompt), scrub (pass, but blank input-state fields of the reply,
as for the pointer's button/modifier mask), and block (default-deny:
refuse safely and log).

Refusing a request without breaking the client
----------------------------------------------
A request cannot simply be dropped.  The server counts requests to
generate sequence numbers, so swallowing one leaves the client's
numbering one ahead of the server's and every later reply is mismatched.
Denials therefore always send *something* upstream:

  * A request expecting no reply is replaced by ``NoOperation``, which
    consumes its sequence number and does nothing.

  * A request expecting a reply is replaced by ``GetInputFocus`` -- also
    harmless, but it does reply.  When that reply comes back, it is
    swapped for the answer the policy decided on.  Using the real reply
    as a barrier is what keeps the substituted answer correctly ordered
    against everything else in the stream; injecting it from the request
    thread would race.

Which of the two a request needs is a table lookup for the core protocol
(``REPLY_REQUESTS``) and cannot be for extensions, whose requests all share
a major opcode of 128 or more.  So an extension that is not on the allowlist
is reported *absent* by ``QueryExtension`` and never asked anything, and each
extension inspector names the reply-bearing requests it refuses itself.

Wherever possible the substituted answer is one applications already
handle: a property that does not exist, a window with no children, a grab
that was already taken.  Errors are a last resort, because Xlib's default
error handler exits the process -- toolkits install their own, but simple
clients do not.

Selections are refused differently, and more cheaply.  The selection atom
in ``ConvertSelection`` is rewritten to an atom nobody owns, so the
*server* generates the standard "no owner" answer by itself, and the
owner never even hears that a paste was attempted -- the data does not
leave the application holding it.  The resulting ``SelectionNotify``
event has its selection field patched back on the way out, so the client
sees a refusal for the selection it actually asked about.
"""

import argparse
import collections
import hashlib
import os
import queue
import re
import shlex
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time

# xfilter_core lives beside this file, and this file is often reached through a
# symlink on $PATH.  Python resolves the script's symlink before setting
# sys.path[0] only from 3.11 on, so on an older interpreter the import would
# look in the symlink's directory and fail; resolving it here works everywhere.
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from xfilter_core import (Connection, CORE_NAMES, Profile,
                          accepted_by_upstream, connect_upstream, cookie_for,
                          listen, pad4, parse_display, printable,
                          read_exactly, read_xauth, upstream_candidates,
                          working_cookie)

# Reverse of CORE_NAMES, so allowlists below can be written as request names
# rather than a wall of opcode numbers.
#: Bumped when behaviour a user could depend on changes.  A package needs a
#: version, and so does the first line of a bug report.
__version__ = "0.9"

_OPCODE = {name: opcode for opcode, name in CORE_NAMES.items()}


def opcodes(*names):
    """The opcode set for these core request names (raises on a typo)."""
    return frozenset(_OPCODE[name] for name in names)

# Extensions we explicitly name as dangerous and refuse.  This is NOT what
# enforces the denial -- default-deny does that: anything not on the allowlist
# (EXTENSION_INSPECTORS below) is already blocked.  This list adds three things
# default-deny cannot: its opcodes are learned and refused from the very first
# request (learn_denied_opcodes, checked first in judge()); the out-of-band
# channels the threat model treats as fatal (MIT-SHM, Composite, DAMAGE, GLX,
# DRI3, Present) are named so their denial is a positive, auditable statement
# printed at startup; and the contradiction guard below makes it a loud startup
# failure -- not a silent hole -- if a future edit ever tries to *allow* one of
# them.  Every one was either never requested by the applications profiled, or
# requested and abandoned (MIT-SHM tries an Attach over a remote connection and
# falls back).
KNOWN_DENIED_EXTENSIONS = {
    "XTEST", "RECORD", "MIT-SHM", "Composite", "DAMAGE", "GLX", "DRI3",
    "Present", "XVideo", "XVideo-MotionCompensation", "SECURITY",
    "XFree86-VidModeExtension", "XFree86-DGA", "DPMS",
}

# Properties on other clients' windows that may still be read: theming,
# settings, and window-manager negotiation.  Everything else -- window
# titles, class names, command lines -- is refused.
#
# _NET_ACTIVE_WINDOW and _NET_CLIENT_LIST are deliberately *absent*, the two
# EWMH root properties that describe other clients rather than the desktop.
#
# _NET_ACTIVE_WINDOW names whichever window the user is currently working in,
# so reading it in a loop is a focus trace of the whole session -- the polling
# twin of the GetInputFocus scrub (OF-1) and the XInput focus reads (XI-1),
# which withhold the same fact one request at a time.  Leaving it readable
# would reopen through EWMH exactly what those close through the core and XInput
# paths.  A client still learns whether *it* has the focus (GetInputFocus
# answers its own case truthfully); what it no longer gets is which other
# application is active.
#
# _NET_CLIENT_LIST is the root's list of every top-level window on the desktop,
# so a single read hands a remote client every foreign window id at once -- the
# enumeration that made the foreign-window attacks (SH-1, XI-1, EV-7) need no
# XID guessing.  QueryTree is already refused on foreign windows (DENY_QUERYTREE)
# and TranslateCoordinates' child field scrubbed; leaving this readable was the
# way around both.  Refused, the three isolation surfaces -- geometry, focus,
# property -- can no longer be swept across the whole desktop from one list.
#
# Removing either here also, by the EV-3 rule, makes the PropertyNotify for it
# on the root a real closure rather than theatre: the read being refused,
# patch_event drops that notification too.  Cost: a taskbar/pager/switcher that
# enumerates or tracks other windows stops working -- not something a forwarded
# application does, and confirmed by e2e to break none of the toolkits.
FOREIGN_PROPERTY_ALLOW = {
    "RESOURCE_MANAGER", "_XSETTINGS_SETTINGS", "_NET_SUPPORTED",
    "_NET_SUPPORTING_WM_CHECK", "_WIN_SUPPORTING_WM_CHECK",
    "_NET_CURRENT_DESKTOP", "_NET_WORKAREA", "_NET_DESKTOP_GEOMETRY",
    "_NET_DESKTOP_VIEWPORT", "_NET_NUMBER_OF_DESKTOPS", "_GTK_WORKAREAS_D4",
    "_GTK_FRAME_EXTENTS", "_NET_FRAME_EXTENTS", "GDK_VISUALS",
}

# ClientMessages a client may send to the root window: this is how any
# application asks the window manager to do something.
EWMH_MESSAGES = {
    "_NET_WM_STATE", "_NET_ACTIVE_WINDOW", "_NET_CLOSE_WINDOW",
    "_NET_WM_MOVERESIZE", "_NET_MOVERESIZE_WINDOW", "_NET_RESTACK_WINDOW",
    "_NET_CURRENT_DESKTOP", "_NET_WM_DESKTOP", "_NET_REQUEST_FRAME_EXTENTS",
    "_NET_WM_FULLSCREEN_MONITORS", "WM_PROTOCOLS", "_NET_SHOWING_DESKTOP",
    "MANAGER", "_XSETTINGS_S0", "WM_CHANGE_STATE", "_NET_WM_ICON_GEOMETRY",
}

GATED_SELECTIONS = {"CLIPBOARD", "PRIMARY", "SECONDARY"}

# What GetSelectionOwner answers about a gated selection somebody else holds.
#
# XFIXES SelectSelectionInput -- the *push* form of "tell me who owns the
# clipboard" -- is refused outright as a snoop on a gated selection, and the
# core poll asks for exactly the same fact: the id of a foreign window, and,
# polled, the moment the user's every copy and mouse-selection changes hands
# (PRIMARY changes owner on each drag-select anywhere on the desktop).  So the
# poll is answered the way the monitor is refused.
#
# The answer is a stand-in rather than None, because None is not a neutral
# lie: a toolkit reads "nobody owns the clipboard" as "there is nothing to
# paste" and greys the menu item out (Qt returns no mime data at all), which
# would break pasting *in* -- the direction --gate ask exists to permit.  A
# constant, non-zero, deliberately invalid id answers "somebody holds it, not
# you", which is all a requestor needs: ConvertSelection names the selection
# atom, not its owner, so nothing downstream dereferences this value.  It
# reads as foreign to every rule that meets it later.  The client's *own*
# ownership is still answered truthfully -- ICCCM has it verify a
# SetSelectionOwner that way, and it is the client's own fact.
SELECTION_OWNER_STANDIN = 0xFFFFFFFF

# The two reasons the clipboard gate refuses under --gate deny, named rather
# than written twice so the log matcher cannot drift from the rules.  The log
# offers the setting that would have allowed it, because "blocked" on its own
# reads as a defect: what the user notices is that copy and paste stopped
# working, with nothing to say a flag governs it.
GATE_REFUSED = "selection gated"
GATE_OWNER_REFUSED = "selection ownership gated"
GATE_HINT = (
    "note: copying out of a forwarded application, and pasting between two of "
    "them,\n      are both refused by --gate deny (the default).  There is one "
    "CLIPBOARD\n      and it is your desktop's, so taking it to hand a sibling "
    "a copy is the\n      same request as taking it to answer your next paste."
    "  --gate ask puts\n      that choice to you instead, and allows both.")

# Whether another client's windows are hidden from QueryTree, and from the
# child field TranslateCoordinates returns.  This is a policy table like the
# ones around it, edited here rather than switched at the command line: a
# security rule that a flag can turn off is a rule that gets turned off, and
# the one place it belongs is with the rest of the policy, where changing it
# is a deliberate edit that shows up in a diff.
#
# It was once "--deny-querytree", off unless asked for, on the theory that it
# "may break window manager negotiation".  Measured, it breaks nothing: every
# end-to-end client renders with it on, and a filtered client does not
# negotiate with the window manager through QueryTree -- it reads EWMH
# properties and sends ClientMessages, both allowed, and QueryTree on its
# *own* window (which is how it finds the frame the window manager reparented
# it into) stays allowed either way.  Only foreign targets are refused.
DENY_QUERYTREE = True

# EWMH messages that act on a window named *inside* the message rather than in
# a request field the policy inspects.  The window manager reads the target out
# of the ClientMessage's own window field and acts on it, so checking only the
# message type let a filtered client close, raise or move any window on the
# desktop through traffic that looks entirely legitimate.
# The tenth pass added the second group: each also acts on the window named in
# the event's own window field, and each was reaching the window manager intact
# on a *foreign* window because it was absent here.
#   WM_CHANGE_STATE          -- iconifies event.window (verified live: a
#                               filtered client minimised a trusted xterm).
#   _NET_WM_STATE            -- adds/removes/toggles a state (fullscreen,
#                               maximized, hidden, above, ...) on event.window.
#                               A test used to assert this was safe on the
#                               belief that it "does not act on the window named
#                               in the message"; per the EWMH spec it does, so
#                               the assertion was wrong and is corrected.  A
#                               client's own-window _NET_WM_STATE is not foreign
#                               and still reaches the fullscreen-spoof check.
#   _NET_WM_MOVERESIZE       -- starts an interactive move/resize of event.window.
#   _NET_WM_DESKTOP          -- moves event.window to another desktop.
#   _NET_WM_FULLSCREEN_MONITORS -- reconfigures which monitors event.window
#                               spans when fullscreen.
EWMH_WINDOW_TARGETS = {
    "_NET_CLOSE_WINDOW", "_NET_ACTIVE_WINDOW", "_NET_MOVERESIZE_WINDOW",
    "_NET_RESTACK_WINDOW", "WM_CHANGE_STATE", "_NET_WM_STATE",
    "_NET_WM_MOVERESIZE", "_NET_WM_DESKTOP", "_NET_WM_FULLSCREEN_MONITORS",
}

# The core requests that are safe to pass as-is: they act on the client's own
# resources (its graphics contexts, pixmaps, colormaps, fonts, cursors and
# windows), or are harmless queries of server-wide configuration.  This is the
# allowlist that makes default-deny possible -- a core request that is neither
# here nor caught by a rule in judge() is blocked and logged, rather than
# passed on trust.  Written as request names, resolved through CORE_NAMES.
#
# Requests that can name *another* client's resource, or that read global
# input/screen/selection state, are deliberately absent: those are ruled on
# individually in judge(), or by the FOREIGN_RESOURCE_REQUESTS table below.
SAFE_CORE = opcodes(
    # colormaps and colors.  These name a colormap, which can be another
    # client's -- but on the TrueColor visuals every modern session uses,
    # colormaps are effectively read-only and allocation cannot exhaust
    # anything, so the isolation is not worth six synthetic replies.
    "CopyColormapAndFree", "AllocColor", "AllocNamedColor", "AllocColorCells",
    "AllocColorPlanes", "QueryColors", "LookupColor",
    # fonts (SetFontPath is absent: the font path is server-global, so a
    # forwarded application emptying it breaks font loading for everyone)
    "OpenFont", "QueryFont", "QueryTextExtents", "ListFonts",
    "ListFontsWithInfo", "GetFontPath",
    # atoms, extensions, harmless config reads
    # (GetInputFocus is deliberately absent: it names whichever window holds
    # focus, another client's included, so judge() scopes its reply instead.)
    "InternAtom", "GetAtomName", "ListExtensions",
    # (GetKeyboardControl is deliberately absent: its reply carries the LED
    # mask -- the live lock state of the keyboard every client shares -- so
    # judge() scrubs that one field and answers the rest of the configuration
    # truthfully.  GetSelectionOwner is absent for the neighbouring reason:
    # it names whichever window holds the clipboard, which is both a foreign
    # window id and a poll of when the user last copied, so judge() answers
    # it with a stand-in.)
    "GetKeyboardMapping", "GetModifierMapping",
    "GetPointerControl", "GetPointerMapping", "GetScreenSaver",
    # Releasing a grab.  Both name nothing but a timestamp -- there is no
    # window to gate -- and a client that may take the pointer or keyboard
    # (judge() rules on that, scoped to its own windows) must be able to give
    # them back.  Allowing the grab and refusing the release is worse than
    # either: the grab then lasts until the client exits, and the rest of the
    # session gets no input in the meantime.
    "UngrabPointer", "UngrabKeyboard",
    # miscellaneous harmless
    "Bell", "NoOperation", "AllowEvents", "SetCloseDownMode",
)

# Requests that name a resource -- a drawable, graphics context, colormap,
# cursor or font -- by an id the client simply states.  X checks no ownership
# on any of these: a client may free a resource it never created, scribble on
# another application's window, or rewrite the graphics context another
# application is drawing with.  That is the untrusted set reaching into the
# trusted one, so each named id gets the same is_foreign() gate the window
# requests have.  The value is the body offsets that must not be foreign; none
# of these expects a reply.
#
# Drawing is included, reversing an earlier judgement that guarding every
# PolyLine was impractical and that drawing onto a foreign drawable was
# mischief rather than disclosure.  It is neither impractical -- the check is
# two integer operations on the common path, see PolicyConnection.is_foreign
# -- nor mere mischief: PutImage and ImageText8 onto a window the user trusts
# paint whatever the remote application likes inside somebody else's frame,
# which is the raw material of a spoofed prompt.
FOREIGN_RESOURCE_REQUESTS = {
    _OPCODE[name]: offsets for name, offsets in {
        # freeing another client's resource destroys it
        "CloseFont": (0,), "FreeGC": (0,), "FreePixmap": (0,),
        "FreeColormap": (0,), "FreeCursor": (0,), "FreeColors": (0,),
        # rewriting the graphics context another client draws with
        "ChangeGC": (0,), "CopyGC": (0, 4), "SetDashes": (0,),
        "SetClipRectangles": (0,), "RecolorCursor": (0,),
        # drawing into another client's window
        "ClearArea": (0,), "PolyPoint": (0,), "PolyLine": (0,),
        "PolySegment": (0,), "PolyRectangle": (0,), "PolyArc": (0,),
        "FillPoly": (0,), "PolyFillRectangle": (0,), "PolyFillArc": (0,),
        "PutImage": (0,), "PolyText8": (0,), "PolyText16": (0,),
        "ImageText8": (0,), "ImageText16": (0,),
        # another client's colormap: its colours, or its installation
        "InstallColormap": (0,), "UninstallColormap": (0,),
        "StoreColors": (0,), "StoreNamedColor": (0,),
    }.items()
}

# Requests that name a drawable or window only to pick a screen and a depth.
# No data flows from it, which is why they were treated as safe -- but a client
# has no reason to point one at another client's window, and a root (the
# ordinary target) is allowed through is_foreign_window.  The value is the body
# offsets carrying the reference.
SCREEN_REFERENCE_REQUESTS = {
    _OPCODE["CreateGC"]: (4,),
    _OPCODE["CreatePixmap"]: (4,),
    _OPCODE["CreateColormap"]: (4,),
}

# The same, for requests that answer something and so cannot simply be dropped.
SCREEN_REFERENCE_REPLIES = {
    _OPCODE["QueryBestSize"]: (0,),
    _OPCODE["ListInstalledColormaps"]: (0,),
}

# Cursor sources: pixmaps and fonts rather than windows, so no root exception.
# A None mask is 0, which is_foreign() already reads as not foreign.
CURSOR_SOURCE_REQUESTS = {
    _OPCODE["CreateCursor"]: (4, 8),
    _OPCODE["CreateGlyphCursor"]: (4, 8),
}

# ChangeWindowAttributes value-mask bits that are per-*client* state: a client's
# event mask on a window is its own, so setting it on somebody else's window
# affects nobody else.  Every other bit -- background, border, colormap, cursor,
# override-redirect, gravity, backing store -- is an attribute of the window
# itself and changes what the window's real owner displays, so on a foreign
# window it is refused.
#
# CWDontPropagate (0x1000) was here on the belief that it, too, is per-client.
# It is not: the do-not-propagate-mask is a single per-*window* attribute
# (GetWindowAttributes returns one value, not one per client), so a client
# setting it on a foreign window changes which events that window stops
# propagating to its ancestors for the whole session -- an integrity write to
# another client's window, the same class as changing its background.  It is a
# window attribute, not per-client state, so it is *not* exempt: only the event
# mask is, and CWDontPropagate on a foreign window is now refused with the rest.
CW_PER_CLIENT = 0x800                    # CWEventMask only

# Requests that modify a window rather than read it: destroy it, map or unmap
# it, restack or resize it, reparent it, or put it in a save set.  Each names
# the window in the first four bytes of its body and none expects a reply.
# These are the write-direction twin of the reads that already get an
# is_foreign() gate: on a foreign window they are a one-line denial of service
# against the rest of the session, or a reparent that adopts another
# application's window and with it that window's input.
WINDOW_WRITE_REQUESTS = opcodes(
    "DestroyWindow", "DestroySubwindows", "ChangeSaveSet", "ReparentWindow",
    "MapWindow", "MapSubwindows", "UnmapWindow", "UnmapSubwindows",
    "ConfigureWindow", "CirculateWindow",
)

# The one extension allowlist, and the single source of truth for it.  An
# extension reaches the server if and only if it appears here, and the value is
# the judge_* method that inspects its requests -- so "allowed" and "inspected"
# are the same fact, and there is no way to admit an extension without an
# inspector or to route to an inspector for an extension that is not admitted.
# Everything else -- an extension nobody profiled, a new one nobody has looked
# at -- is blocked and logged by default-deny rather than passed.
#
# judge() dispatches through this table; QueryExtension and ListExtensions use
# ALLOWED_EXTENSIONS (its keys) to decide what a client may see; and main()
# checks every method here exists on PolicyConnection, so a typo or a missing
# inspector is a loud startup failure, not a silent block.
EXTENSION_INSPECTORS = {
    "RENDER": "judge_render",
    "XFIXES": "judge_xfixes",
    "XInputExtension": "judge_xinput",
    "SHAPE": "judge_shape",
    "XKEYBOARD": "judge_xkb",
    "RANDR": "judge_randr",
    "SYNC": "judge_sync",
    "DOUBLE-BUFFER": "judge_dbe",
    "XC-MISC": "judge_xcmisc",
    "XINERAMA": "judge_xinerama",
    "Generic Event Extension": "judge_generic_event",
    "BIG-REQUESTS": "judge_big_requests",
}
ALLOWED_EXTENSIONS = frozenset(EXTENSION_INSPECTORS)

# A capability belongs on exactly one side: allowed (inspected) or known-denied,
# never both.  XVideo was once in both; evaluation order saved it -- judge()
# consults the denied opcodes first -- but a dead allowlist entry is a trap for
# the next change to the ordering, so the contradiction fails loudly here
# instead of resolving silently.
_contradiction = KNOWN_DENIED_EXTENSIONS & ALLOWED_EXTENSIONS
if _contradiction:
    raise RuntimeError("extension both denied and allowed: %s"
                       % ", ".join(sorted(_contradiction)))

# Properties an application sets on its own windows that say who it is.
# Applications open many connections -- thirteen, in one profiled run --
# so the useful unit for a decision is the application, and this is how
# the proxy recovers it from traffic it is already relaying.
IDENTITY_PROPERTIES = {
    "WM_CLASS": "class", "_NET_WM_NAME": "name", "WM_NAME": "name",
    "_NET_WM_PID": "pid", "WM_CLIENT_MACHINE": "host",
}

# Requests that expect a reply, so a denial has to answer something.
REPLY_REQUESTS = {
    3, 14, 15, 16, 17, 20, 21, 23, 26, 31, 38, 39, 40, 43, 44, 47, 48, 49,
    50, 52, 73, 83, 84, 85, 86, 87, 91, 92, 97, 98, 99, 101, 103, 106, 108,
    110, 116, 117, 118, 119,
}

# Event-mask bits that turn a window into an input tap.
#
# EnterWindow (0x10) and LeaveWindow (0x20) are here for the reason the tenth
# pass found: a crossing event carries the *global* pointer position (root_x,
# root_y) and the live keyboard modifier state (its `state` field), so
# selecting Enter/LeaveWindow on the root -- a window the client does not own
# -- is a whole-desktop pointer trace and a modifier logger in one, reached
# past both the QueryPointer position bounding and the XkbGetState/StateNotify
# scrub the ninth pass installed.  PointerMotion (0x40) was already refused, so
# the attack simply moved to the crossing bits beside it; they are now refused
# on a foreign window the same way.  On the client's *own* windows these still
# pass (hover and tooltips need them), where the position is the irreducible
# "pointer over my window" case QueryPointer already allows.
INPUT_EVENT_BITS = (0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100 |
                    0x200 | 0x400 | 0x800 | 0x1000 | 0x2000 | 0x4000)

# Event *codes* (not mask bits) that carry forged input when sent by SendEvent:
# KeyPress, KeyRelease, ButtonPress, ButtonRelease, MotionNotify.  Refused to
# the PointerWindow/InputFocus destinations, which resolve to a trusted window.
SYNTHETIC_INPUT_CODES = frozenset({2, 3, 4, 5, 6})

#: Core events that carry a keystroke.  They are delivered only while a window
#: of the application holds the focus: see PolicyConnection._focus_is_ours.
KEY_EVENT_CODES = frozenset({2, 3})

# Names for the fixed events patch_event can withhold, for the one line the
# operation log prints when it does.  Only droppable events need a name;
# anything else is labelled by its code.
DROPPABLE_EVENT_NAMES = {2: "KeyPress", 3: "KeyRelease", 28: "PropertyNotify"}

# Core events that carry the pointer's position: ButtonPress, ButtonRelease,
# MotionNotify, EnterNotify, LeaveNotify.  Each has the same shape past its
# header -- root window at 8, event window at 12, child at 16, the root-relative
# position at 20, the window-relative one at 24, the modifier state at 28 --
# which is what lets one rule bound all five.
POINTER_EVENT_CODES = frozenset({4, 5, 6, 7, 8})

# Event-mask bits that reach outside the client through the *event* stream
# rather than through a reply, and so are refused on a window the client does
# not own -- the root included, which is where both of them matter.
#
#   SubstructureNotify (0x80000) on the root delivers CreateNotify,
#   DestroyNotify, MapNotify, UnmapNotify, ConfigureNotify and ReparentNotify
#   for every top-level window on the display: ids, geometry, stacking, and the
#   timing of every application opening and closing.  That is the enumeration
#   DENY_QUERYTREE and the blank GetGeometry/GetWindowAttributes exist to
#   close, reached by a route none of them cover -- and better for a watcher
#   than polling ever was, because the client selects once and the server
#   pushes for the rest of the session.
#
#   SubstructureRedirect (0x100000) on the root makes the client the window
#   manager: every MapRequest and ConfigureRequest from every other client is
#   redirected to it instead of being executed, so it can refuse to map your
#   windows, move them, or swallow them.  Only one client may hold it, so with
#   a window manager running the server answers BadAccess -- but the policy
#   should not be resting on another client having got there first.
#   FocusChange (0x200000) on the root reports every focus transition in the
#   session.  No toolkit needs focus events on a window it does not own -- it
#   watches its own -- so refusing this costs nothing.  It does not close focus
#   tracking on its own: see the GetInputFocus note in AUDIT.md.
SUBSTRUCTURE_EVENT_BITS = 0x80000 | 0x100000
FOREIGN_EVENT_BITS = INPUT_EVENT_BITS | SUBSTRUCTURE_EVENT_BITS | 0x200000
CW_EVENT_MASK = 0x800

# What a client may select on a window it does NOT own.  This used to be the
# other way round -- a block-list of the event bits to refuse (input taps,
# substructure, focus), with everything else allowed -- which is fail-open: any
# event bit nobody thought to add to the block-list passed.  That is how the
# tenth pass found the crossing bits leaking, and, right beside them,
# StructureNotify (0x20000): selected on a foreign window it pushes that window's
# every ConfigureNotify -- its position and size as they change -- the geometry
# GetGeometry is blanked to withhold, arriving in real time through the event
# stream.  ResizeRedirect (0x40000) let a client intercept another window's
# resizes, VisibilityChange (0x10000) reported when it was obscured, and
# ColormapChange (0x800000) its colormap installs -- all allowed by omission.
#
# So the gate is now an allowlist, like every durable rule in this file: on a
# foreign window a selection may name ONLY these bits, and anything else is
# refused and logged.  Nothing is on it but PropertyChange, because that is the
# one event a client has a real reason to select on another window -- a GTK
# client watches PropertyChangeMask on the settings-manager window for theme
# changes and on the root for _NET_* -- and even then the resulting
# PropertyNotify is filtered by the EV-3 handler for atoms the client may not
# read.  Everything else earns its place here by a real application needing it,
# named in the log; the default is refuse.
FOREIGN_EVENT_MASK_ALLOW = 0x400000                      # PropertyChange

# ConfigureWindow's value-mask bit for the sibling to stack against.
CW_SIBLING = 0x20

# ChangeWindowAttributes/CreateWindow value-mask bit for override-redirect --
# the one attribute that makes a window bypass the window manager (no frame, no
# WM control), which is what a fullscreen spoof needs.  ConfigureWindow's width
# and height value-mask bits, for spotting a resize into a fullscreen overlay.
CW_OVERRIDE_REDIRECT = 0x200
CONFIGURE_WIDTH = 0x4
CONFIGURE_HEIGHT = 0x8

# A window counts as "fullscreen" once it covers this fraction of the screen in
# both dimensions.  The spoof wants the whole screen; the fraction leaves room
# for a window that is screen-sized-minus-a-panel without missing an overlay.
FULLSCREEN_FRACTION = 0.9

# EWMH state atoms: the second route to a borderless fullscreen window is to ask
# the window manager for it, by adding _NET_WM_STATE_FULLSCREEN to _NET_WM_STATE
# (via a ClientMessage to the root, or by setting the property directly).
NET_WM_STATE = "_NET_WM_STATE"
NET_WM_STATE_FULLSCREEN = "_NET_WM_STATE_FULLSCREEN"
# _NET_WM_STATE ClientMessage actions: 0 remove, 1 add, 2 toggle.  Only adding
# or toggling fullscreen is gated; removing it is always fine.
NET_WM_STATE_ADDING = (1, 2)

# XKEYBOARD and RANDR are inspected the other way round from RENDER and
# XFIXES: rather than naming the requests to refuse, these name the ones to
# allow, and everything else in the extension is blocked.  Enumerating the
# writes would leave the extension default-allow internally -- the same shape
# of hole as passing it wholesale on its major opcode, which is what let
# XkbSetMap remap the shared keyboard past a policy that blocks
# ChangeKeyboardMapping.  The cost is over-blocking rather than under-blocking,
# and the operation log names anything an application turned out to need.

# XKEYBOARD: queries, and the per-connection state a toolkit sets for itself.
# UseExtension (0) is the version handshake every client opens with, and
# PerClientFlags (21) is how essentially every toolkit asks for detectable
# auto-repeat; Bell (3) is here because core Bell already is.  Everything
# absent -- SetMap 9, SetControls 7, SetNames 18, SetCompatMap 11,
# LatchLockState 5, SetIndicatorMap 14, SetNamedIndicator 16, SetGeometry 20,
# SetDeviceInfo 25 -- writes keyboard state shared with every other client.
XKB_ALLOWED = {0, 1, 3, 4, 6, 8, 10, 12, 13, 15, 17, 19, 21, 22, 24}

# The XKB events a client may keep.  This was a block-list -- drop
# XkbStateNotify (2), pass everything else -- which is the fail-open shape the
# tenth pass spent itself inverting everywhere else, and it left the *lock*
# state of the keyboard streaming out beside the modifier state that pass
# closed: IndicatorStateNotify (4) reports every Caps/Num/Scroll Lock change,
# and ExtensionDeviceNotify (11) carries the same LED state for a device.
# Both were measured arriving through the proxy while StateNotify was
# correctly withheld.  The two events toolkits actually need are
# XkbNewKeyboardNotify (0) and XkbMapNotify (1) -- the keymap changed, reread
# it -- so those are the allowlist and the other ten are dropped: the
# indicator pair, ControlsNotify (3), IndicatorMapNotify (5), NamesNotify (6),
# CompatMapNotify (7), BellNotify (8), and the two that can carry a keycode,
# ActionMessage (9) and AccessXNotify (10).
XKB_EVENT_ALLOW = {0, 1}

# The XkbGetDeviceInfo facets that answer with a device's indicator state:
# XkbXI_IndicatorNames (1<<2), IndicatorMaps (1<<3) and IndicatorState (1<<4).
# The state rides along with the names and the maps -- the reply's per-feedback
# record carries it whenever any LED facet is asked for -- so all three are
# stripped together, and a request that wants button actions or the device
# list keeps working.
XKB_DEVICE_INDICATORS = 0x1C

# GetKbdByName (23) reads like a query and is not one: with the load flag set
# it replaces the server's keymap, so it is a write wearing a read's name.
# SetDebuggingFlags (101) is the other blocked request that expects a reply.
XKB_REPLIES = {23, 101}

# RANDR: the monitor layout every application reads for DPI and placement,
# plus event selection.  The configuration writes -- SetCrtcConfig 21,
# SetScreenConfig 2, SetScreenSize 7, SetOutputPrimary 30, SetPanning 29,
# SetCrtcGamma 24, SetCrtcTransform 26, CreateMode 16, AddOutputMode 18, the
# output and provider property writes, and the leases -- change the shared
# screen for the whole session and are absent.
RANDR_ALLOWED = {0, 4, 5, 6, 8, 9, 10, 11, 15, 20, 22, 23, 25, 27, 28, 31,
                 32, 33, 36, 37, 41, 42}

# The RANDR writes that expect a reply, so a refusal has to answer something.
RANDR_REPLIES = {2, 16, 21, 29, 45}

# RENDER, XFIXES, XInput and SHAPE were the last extensions passing an
# unrecognised request on trust.  They are now allowlisted like XKEYBOARD and
# RANDR, so a minor opcode nobody has looked at -- a future addition, or one
# this project never profiled -- is refused rather than forwarded.  The lists
# are wide, because these four really are how modern toolkits draw and handle
# input; the point is not to narrow them but to make "unknown" mean "refused".

# RENDER: every request the protocol defines.  The gaps (3 QueryDithers,
# 9 Scale, 14-16, 21) are requests no server implements.
RENDER_ALLOWED = {0, 1, 2, 4, 5, 6, 7, 8, 10, 11, 12, 13, 17, 18, 19, 20, 22,
                  23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36}
RENDER_REPLIES = {3}

# The RENDER requests that name a Picture or GlyphSet the client may not own:
# freeing one destroys another application's drawing surface, and compositing
# into one paints inside it.  Offsets skip the PICTFORMAT fields, which the
# *server* allocates and which would read as foreign to every check.
RENDER_FOREIGN = {
    5: (0,), 6: (0,), 7: (0,), 8: (4, 8, 12),
    10: (4, 8), 11: (4, 8), 12: (4, 8), 13: (4, 8),
    18: (4,), 19: (0,), 20: (0,), 22: (0,),
    23: (4, 8, 16), 24: (4, 8, 16), 25: (4, 8, 16),
    26: (4,), 27: (4,), 28: (0,), 30: (0,), 32: (0,),
}

# XFIXES: the region algebra, the save set, cursor naming and the barriers.
# The cursor *image* requests (3, 4, 25, 29) are absent -- they are refused by
# name in judge_xfixes for the leak they are, not merely left off this list.
XFIXES_ALLOWED = {0, 1, 2, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                  19, 20, 21, 22, 23, 24, 26, 27, 28, 30, 31, 32}
XFIXES_REPLIES = {19, 24}

# XFIXES requests naming a region, graphics context, picture, cursor, barrier
# or window that may be another client's.  Offset 0 is skipped wherever it is
# the *new* id the client is creating.
#
# SetGCClipRegion (20) and SetPictureClipRegion (22) carry the region at offset
# 4 and their (xOrigin, yOrigin) pair at 8.  Both were listed against offset 8,
# so the check read the two 16-bit origins as one resource id: a foreign region
# went through unexamined, and an ordinary request whose clip origin was not
# (0, 0) was silently dropped for naming a "resource" that was really a pair of
# coordinates.  Wrong in both directions from one wrong offset.
XFIXES_FOREIGN = {
    1: (4,), 6: (4,), 7: (4,), 8: (4,), 9: (4,),
    10: (0,), 11: (0,), 12: (0, 4), 13: (0, 4, 8), 14: (0, 4, 8),
    15: (0, 4, 8), 16: (0, 12), 17: (0,), 18: (0, 4), 19: (0,),
    20: (0, 4), 22: (0, 4), 23: (0,), 24: (0,), 26: (0, 4), 27: (0,),
    28: (0, 4), 30: (0,), 31: (4,), 32: (0,),
}

# XInput: the device queries, the per-client event selection and grabs, and
# the XInput2 surface toolkits use.  Absent, and so refused: the requests that
# rewrite a device's key, modifier or button mapping (25, 27, 29 -- the
# XInput1 twins of the core remap rules and of XkbSetMap), the ones that read
# input state or history directly (30 QueryDeviceState is a keylogger,
# 10 GetDeviceMotionEvents the twin of the blocked GetMotionEvents), the ones
# that reattach or reconfigure devices for the whole server (5, 11, 12, 23,
# 33, 35, 43, 44), device properties, which are server-global (37, 38, 57,
# 58), and 31 SendExtensionEvent, which synthesises input at another window.
XI_ALLOWED = {1, 2, 3, 4, 6, 7, 8, 9, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
              24, 26, 28, 32, 34, 36, 39, 40, 41, 42, 45, 46, 47, 48, 49, 50,
              51, 52, 53, 54, 55, 56, 59, 60, 61}
XI_REPLIES = {5, 10, 11, 12, 27, 29, 30, 33, 35}

# SHAPE: the whole extension, which is small.
SHAPE_ALLOWED = {0, 1, 2, 3, 4, 5, 6, 7, 8}
SHAPE_REPLIES = {0, 5, 7, 8}

# SHAPE requests that reshape a window, each naming it at offset 4.  On a
# foreign window these make another application's window click-through or
# invisible -- the WINDOW_WRITE_REQUESTS attack arriving through an extension.
SHAPE_WINDOW_WRITES = {1, 2, 3, 4}

# ShapeMask (2) and ShapeCombine (3) name a *source* drawable at offset 12 --
# a one-bit pixmap for the first, a window for the second -- and copy its shape
# onto the destination at offset 4.  Only the destination was gated, so a
# foreign source into an own destination was the CopyArea read-back in shape
# form: combine another application's window shape into a window you own, then
# ask ShapeQueryExtents about your own window, which is allowed, and the
# outline SH-1 blanked comes back one field over.
SHAPE_SOURCE_DRAWABLES = {2, 3}

# SHAPE requests that *read* a window's shape, each naming it at offset 0.
# ShapeQueryExtents (5) and ShapeGetRectangles (8) hand back the window's
# bounding size and outline -- the foreign window metadata GetGeometry is
# blanked to withhold, reached one opcode over; ShapeInputSelected (7) reports
# whether input shaping is selected on it.  On a foreign window all three are
# answered blank rather than truthfully (SH-1).
SHAPE_WINDOW_READS = {5, 7, 8}

# XInput reads that answer about a *window* rather than about the client
# asking, each naming it at offset 0 and each expecting a reply.
# GetSelectedExtensionEvents (7) reports every client's event classes on it,
# GetDeviceDontPropagateList (9) the window's do-not-propagate list -- the read
# twin of ChangeDeviceDontPropagateList (8), already refused on a foreign
# window -- and XIGetClientPointer (45) names the pointer device of whichever
# client owns it.  On a foreign window all three enumerate another client's
# input wiring, so they are answered blank (SH-1's treatment, in XInput).
#
# XIGetSelectedEvents (60) looks like a fourth and is deliberately absent: it
# reports only what the *asking* client selected on the window, so there is
# nothing of anyone else's in the reply.  Its write side, XISetClientPointer
# (44), is off XI_ALLOWED already.
XI_FOREIGN_WINDOW_READS = {7, 9, 45}

# XInput2 event-mask bits that make a window an input tap: key, button,
# pointer motion and touch, in both their ordinary and their "raw" forms.
# Selecting any of these on a window the client does not own -- the root
# above all -- is a working keylogger.
XI_TAP_MASK = sum(
    1 << bit for bit in (2, 3, 4, 5, 6,          # Key/Button/Motion press+release
                         13, 14, 15, 16, 17,     # their Raw* forms
                         18, 19, 20, 22, 23, 24))  # Touch and RawTouch

# XInput2 event-mask bits that are not "taps" but still carry the global
# pointer position and the modifier state -- the XI2 twins of the core
# crossing and focus events.  XI_Enter/XI_Leave (7, 8) and XI_FocusIn/
# XI_FocusOut (9, 10) each carry root_x/root_y (FP1616) and a full modifier
# set, so selecting them on the root is the same whole-desktop pointer and
# modifier trace the core crossing bits are, reached through XInput2 -- and
# XI2 events are delivered as GenericEvents, which the relay forwards verbatim
# with no event-side filter, so the request-side selection gate is the only
# place to stop them (tenth pass).  The device-plumbing events a toolkit does
# select on the root -- XI_HierarchyChanged (11), XI_DeviceChanged (1),
# XI_PropertyEvent (12) -- are deliberately absent: they name no position and
# no modifier, so they stay allowed.
XI_CROSSING_FOCUS_MASK = sum(1 << bit for bit in (7, 8, 9, 10))

# Everything a foreign XISelectEvents must not ask for: the taps and the
# position/modifier-bearing crossing and focus events together.
XI_FOREIGN_EVENT_MASK = XI_TAP_MASK | XI_CROSSING_FOCUS_MASK

# Generic (XGE) events the proxy forwards; everything else is dropped and logged.
#
# XGE is the one server-to-client channel the relay cannot rewrite field by
# field the way patch_event rewrites a fixed event -- an XInput2 event's layout
# depends on its evtype, and the relay does not parse it.  Until the tenth pass
# every XGE was forwarded verbatim, which made the request-side selection gate
# the *only* thing standing between a client and an XI2 event: a leak-bearing
# event a client could select on its own window (an XI2 crossing carries the
# global pointer position and the modifiers) reached it unfiltered.
#
# So XGE is now default-deny like everything else: an (extension, evtype) pair
# is forwarded only if it is listed here, and anything not listed is dropped and
# named once in the operation log -- start closed, then add back exactly what a
# real application turns out to need, each entry earning its place.  Dropping an
# event never desyncs the stream (events are not counted, unlike requests), so
# the cost of an over-block here is a missing event, not a broken connection.
#
# The value is a set of allowed evtypes, or the string "all" for an extension
# whose every event is judged safe.  It began empty and was grown to exactly the
# XInput2 events a real toolkit turned out to need -- measured, not assumed:
# with the list empty, a GTK3 client rendered but was deaf to the mouse and
# keyboard (GTK delivers pointer/button/key input as XInput2 events, so an empty
# allowlist withholds every one); with the input, device-housekeeping, touch and
# gesture events below allowed, the same client took clicks and typed text
# normally.
#
# XInput2 evtypes:
#    1 DeviceChanged   2 KeyPress    3 KeyRelease   4 ButtonPress
#    5 ButtonRelease   6 Motion      7 Enter        8 Leave
#    9 FocusIn        10 FocusOut   11 HierarchyChanged  12 PropertyEvent
#   13-17 Raw*        18-21 Touch*  22-24 RawTouch*  25 BarrierHit
#   26 BarrierLeave   27-30 Gesture*
#
# Deliberately *excluded*, and why:
#   7, 8 (Enter/Leave) and 9, 10 (FocusIn/FocusOut) carry the global pointer
#     position and the modifier state -- the tenth-pass leak -- and, unlike a
#     reply, an XGE cannot be scrubbed field by field, so it is pass-or-drop.
#     The GTK client above needed none of them to click or type, so they stay
#     dropped; a client's own-window core Enter/Leave/Focus (fixed events) still
#     flow, which is why blanking the XI2 twins costs it nothing here.  If a
#     real application's menus or tooltips turn out to need them, they are the
#     first add-back -- with the understanding that they reintroduce exactly the
#     own-window position/modifier residual core crossing events already carry.
#   13-17 and 22-24 (the Raw* forms) are the device-wide taps XISelectEvents is
#     refused for on a foreign window; no application needs them on its own
#     windows, so they are not passed here either.
GENERIC_EVENT_ALLOW = {
    "XInputExtension": {1, 2, 3, 4, 5, 6, 11, 12,
                        18, 19, 20, 21, 25, 26, 27, 28, 29, 30},
}

# The last six extensions were passed on their major opcode alone.  They now get
# a minor-opcode allowlist like the other inspected extensions, so a request
# nobody has looked at -- a future addition, one this project never profiled --
# is refused rather than forwarded.  Two of them, SYNC and DOUBLE-BUFFER, also
# name resources that may be another client's, and those get a foreign gate.

# SYNC: counters, alarms, fences, and per-client priority.  Creating and using
# the client's *own* sync objects is fine; the requests that modify or destroy
# an object by id, or set another client's scheduling priority, are refused when
# the id is foreign -- the FOREIGN_RESOURCE_REQUESTS shape, in an extension.
SYNC_ALLOWED = set(range(0, 20))
SYNC_REPLIES = {0, 1, 5, 10, 13, 18}
# minor -> offsets of an *existing* resource id (skipping the new id a Create
# names).  All of these expect no reply, so a foreign one is dropped silently.
# This is the WRITE/destroy side only -- the eighth pass gated it and left the
# read side open.
SYNC_FOREIGN = {
    3: (0,), 4: (0,), 6: (0,),        # Set/Change/DestroyCounter
    9: (0,), 11: (0,),                # Change/DestroyAlarm
    12: (0,),                         # SetPriority (id names the target client)
    15: (0,), 16: (0,), 17: (0,),     # Trigger/Reset/DestroyFence
}
# The READ side, which was ungated: each of these *returns* a foreign sync
# object's state, so on a foreign resource it is a disclosure, not a
# nuisance.  The one that matters is QueryCounter on a server *system* counter
# -- `IDLETIME`, which every real Xorg exposes: its value is milliseconds since
# the user last touched the keyboard or pointer, so polling it is a whole-session
# activity/idle trace, the same silhouette the ninth pass closed for focus,
# pointer and modifiers.  QueryAlarm, QueryFence and GetPriority read another
# client's alarm/fence/priority.  A system counter is server-created, so it
# reads as foreign; a client's own counters stay readable.  Each expects a
# reply, so a foreign one is answered blank (a zeroed reply: value 0, fence not
# triggered) rather than dropped.
SYNC_FOREIGN_READS = {
    5: (0,),                          # QueryCounter (IDLETIME is the leak)
    10: (0,),                         # QueryAlarm
    13: (0,),                         # GetPriority (id names a client)
    18: (0,),                         # QueryFence
}

# DOUBLE-BUFFER: back buffers for flicker-free drawing.  A back buffer is
# allocated against a window and named by its own id; naming a foreign window
# or buffer reaches into another client's drawing.
DBE_ALLOWED = {0, 1, 2, 3, 4, 5, 6, 7}
DBE_REPLIES = {0, 6, 7}

# Every admitted minor of a gated extension is classified as exactly one of two
# things, and the pair is required to *partition* the extension's allowlist:
#
#   GATED -- a minor with a gate in its judge_* method (an is_foreign check on a
#     resource it names), listed here as the gate tables it reads plus the few
#     minors gated by an inline `if minor == N` branch.
#   SAFE  -- a minor that reaches the inspector's tail and is allowed there: a
#     version or capability query, or a Create that mints a new id in the
#     client's own range.  It names no foreign resource and returns no session
#     state.
#
# The point is the import-time check below: SAFE and GATED must be disjoint and
# together cover the whole allowlist, so *every* admitted minor has been
# deliberately put in one bucket or the other.  A minor added to a *_ALLOWED
# list without also being classified here fails the check at import -- a loud
# error, not a silent allow-tail.  This is what turns "allow unless blocked"
# (the fail-open shape that kept yielding findings one request at a time, the
# SYNC read side the latest) into "admit only what is classified": the allow
# still happens at the tail, but the allowlist itself cannot grow without the
# classification being updated to match.
#
# A few SAFE entries name a resource a later pass may still want to gate --
# RENDER 31 (CreateAnimCursor names a cursor list) and the RENDER gradient
# Creates.  They are SAFE today, but listing them here rather than burying them
# in an allow-tail is the point: the classification is visible and auditable,
# and re-gating one is a one-line move from SAFE to GATED -- which is exactly
# how SYNC Await/CreateAlarm (7/8) were closed, once their IDLETIME idle-timing
# route was judged worth the gate rather than left as a documented residual.
RENDER_SAFE = {0, 1, 2, 17, 29, 31, 33, 34, 35, 36}
RENDER_GATED = {4} | set(RENDER_FOREIGN)
XFIXES_SAFE = {0, 5}
XFIXES_GATED = {2, 21} | set(XFIXES_FOREIGN)
XI_SAFE = {1, 2, 3, 4, 14, 16, 18, 19, 24, 26, 28, 32, 34, 36, 39,
           47, 48, 52, 53, 55, 56, 59, 60}
XI_GATED = {6, 8, 13, 15, 17, 20, 21, 22, 40, 41, 42, 46, 49, 50, 51, 54, 61} \
    | XI_FOREIGN_WINDOW_READS
XKB_SAFE = {0, 1, 3, 6, 8, 10, 13, 17, 19, 21, 22}
XKB_GATED = {4, 12, 15, 24}
RANDR_SAFE = {0, 4, 5, 6, 8, 9, 10, 11, 15, 20, 22, 23, 25, 27, 28, 31, 32,
              33, 36, 37, 41, 42}
RANDR_GATED = set()
SHAPE_SAFE = {0}
SHAPE_GATED = set(SHAPE_WINDOW_WRITES) | set(SHAPE_WINDOW_READS) \
    | set(SHAPE_SOURCE_DRAWABLES) | {6}
SYNC_SAFE = {0, 1, 2, 19}
SYNC_GATED = set(SYNC_FOREIGN) | set(SYNC_FOREIGN_READS) | {7, 8, 14}
DBE_SAFE = {0, 4, 5, 6}
DBE_GATED = {1, 2, 3, 7}

# The partition check: every admitted minor is classified exactly once.
for _label, _safe, _gated, _allowed in (
        ("RENDER", RENDER_SAFE, RENDER_GATED, RENDER_ALLOWED),
        ("XFIXES", XFIXES_SAFE, XFIXES_GATED, XFIXES_ALLOWED),
        ("XInput", XI_SAFE, XI_GATED, XI_ALLOWED),
        ("XKEYBOARD", XKB_SAFE, XKB_GATED, XKB_ALLOWED),
        ("RANDR", RANDR_SAFE, RANDR_GATED, RANDR_ALLOWED),
        ("SHAPE", SHAPE_SAFE, SHAPE_GATED, SHAPE_ALLOWED),
        ("SYNC", SYNC_SAFE, SYNC_GATED, SYNC_ALLOWED),
        ("DOUBLE-BUFFER", DBE_SAFE, DBE_GATED, DBE_ALLOWED)):
    _allowed = set(_allowed)
    _overlap = _safe & _gated
    _unclassified = _allowed - _safe - _gated
    _phantom = (_safe | _gated) - _allowed
    if _overlap or _unclassified or _phantom:
        raise RuntimeError(
            "%s minor classification is not a partition of the allowlist: "
            "in both SAFE and GATED=%s, admitted but unclassified=%s, "
            "classified but not admitted=%s"
            % (_label, sorted(_overlap), sorted(_unclassified),
               sorted(_phantom)))

# The read-only extensions: a minor-opcode allowlist is the whole policy,
# because none of them names a foreign resource or reaches a guarded capability.
# XINERAMA answers screen-layout queries (the class RANDR already answers);
# XC-MISC hands the client more of its own XIDs; Generic Event Extension and
# BIG-REQUESTS are version handshakes.  Each has a one-line judge_* method
# (below) that defers to _judge_minor_allowlist with (allowed, reply-bearing).
XINERAMA_ALLOWED = XINERAMA_REPLIES = {0, 1, 2, 3, 4, 5}
XCMISC_ALLOWED = XCMISC_REPLIES = {0, 1, 2}
GENERIC_EVENT_ALLOWED = GENERIC_EVENT_REPLIES = {0}
BIG_REQUESTS_ALLOWED = BIG_REQUESTS_REPLIES = {0}

# A valid atom nobody ever owns as a selection, used to make the server
# refuse a gated ConvertSelection on our behalf (MIN_SPACE, a font
# property predefined since X11R1).
# Every atom name the policy decides on, gathered from the tables that name
# them rather than listed again here -- a rule that matches on a name the proxy
# has not resolved is a rule that does not run, so this set is derived from the
# rules and cannot fall behind them.  main() resolves it against the real
# server before any client connects and seeds the profile, so `atom_name()`
# answers for all of these whether or not the client ever interned one.
POLICY_ATOMS = (frozenset(FOREIGN_PROPERTY_ALLOW)
                | frozenset(EWMH_MESSAGES)
                | frozenset(EWMH_WINDOW_TARGETS)
                | frozenset(IDENTITY_PROPERTIES)
                | frozenset(GATED_SELECTIONS)
                | frozenset({NET_WM_STATE, NET_WM_STATE_FULLSCREEN}))

UNOWNED_ATOM = 43

NOOP = 127
GET_INPUT_FOCUS = 43
BAD_ACCESS = 10
#: What a server answers when it has never heard of a request's major opcode.
#: It is what a client would get from a server that genuinely lacked a hidden
#: extension, which is why refusing one is answered with it.
BAD_REQUEST = 1


#: The upstream connection the startup learning runs on, kept open for the life
#: of the proxy.  It is deliberately never closed: see _learn_setup.
_anchor = None
_anchor_lock = threading.Lock()
_focus_cache = (0.0, None)

#: How long the answer to "who has the focus?" is reused.  Short: the question
#: is asked on a local socket and only while events are arriving, and a stale
#: answer is a keystroke delivered to the wrong client.  Measured at 50ms, the
#: first key after a focus change slipped through; at 10ms it does not, and a
#: burst of typing still asks only a hundred times a second at worst.
FOCUS_CACHE_SECONDS = 0.01


def focus_window(endian="<"):
    """Which window the *server* says has the input focus, or None.

    Asked on the proxy's own upstream connection, which is what makes it
    usable: the proxy cannot inject a request into a client's stream without
    desynchronising every reply after it, but the anchor connection it already
    holds open for startup learning is a client of its own, and a question
    asked there costs the filtered client nothing.

    This is what lets a keyboard grab be *allowed* -- menus need it -- while
    the keystrokes it would steal are withheld: a key event is delivered only
    while a window of this application holds the focus, which is the same
    "the user is working in this application" test the whole policy rests on.
    """
    global _focus_cache
    now = time.time()
    when, window = _focus_cache
    if now - when < FOCUS_CACHE_SECONDS:
        return window
    with _anchor_lock:
        if _anchor is None:
            return None
        try:
            _anchor.sendall(struct.pack(endian + "BBH", GET_INPUT_FOCUS, 0, 1))
            # Read past anything that is not the reply.  The anchor is an
            # ordinary client, so the server sends it unsolicited events --
            # MappingNotify goes to everybody when a keymap changes -- and
            # reading one *as* the reply made this answer "I don't know",
            # which the caller reads as "the client's own window has focus".
            # Measured: exactly one keystroke of a captured word survived,
            # every time, because one MappingNotify arrived per run.  A
            # fail-open in the machinery written to close a fail-open.
            window = None
            while True:
                message = read_exactly(_anchor, 32)
                if not message:
                    return None
                if message[0] == 1:                      # the reply
                    window = struct.unpack_from(endian + "I", message, 8)[0]
                    break
                if message[0] == 0:                      # an error
                    return None
                if message[0] & 0x7F == 35:              # a generic event
                    extra = struct.unpack_from(endian + "I", message, 4)[0] * 4
                    if extra:
                        read_exactly(_anchor, extra)
        except OSError:
            return None
    _focus_cache = (now, window)
    return window


def _learn_setup(target, cookie):
    """The upstream connection the startup questions are asked on, and its
    byte order.  Opened once and **held open** for the life of the process.

    Used at startup to ask the real server things whose answers are stable for
    its whole life -- extension opcodes, event bases, the atom ids the policy
    decides on -- so the proxy can act on them from a client's very first
    request.

    Holding it open is not an optimisation, it is what makes the answers true.
    An X server **resets when its last client disconnects**, and a reset throws
    away the whole atom table.  These helpers used to open a connection, learn,
    and close it -- so when the proxy was the only client, the close reset the
    server and destroyed the very atoms it had just interned.  The proxy then
    enforced ids that no longer meant anything: measured on a bare server, it
    reported CLIPBOARD as atom 230 while the first client to connect was handed
    230 for a selection of its own, so the clipboard gate fired on an unrelated
    selection and the real CLIPBOARD went ungated by id.  Every id-keyed rule
    was affected, and the seeded atom *names* were worse than absent -- a
    foreign property read is admitted by name, so a stale name could admit a
    read of somebody else's WM_NAME.

    One connection, held, means no reset while the proxy runs and every id it
    learned stays the id the server will hand its clients.
    """
    global _anchor
    endian = "<" if sys.byteorder == "little" else ">"
    if _anchor is not None:
        return _anchor, endian
    order = b"l" if sys.byteorder == "little" else b"B"
    name, data = cookie
    sock = connect_upstream(target)
    setup = struct.pack(endian + "cxHHHH2x", order, 11, 0,
                        len(name), len(data))
    setup += name + b"\0" * pad4(len(name)) + data + b"\0" * pad4(len(data))
    sock.sendall(setup)
    head = read_exactly(sock, 8)
    if not head or head[0] != 1:
        sock.close()
        return None, endian
    read_exactly(sock, struct.unpack(endian + "H", head[6:8])[0] * 4)
    _anchor = sock
    return sock, endian


def learn_extension_opcodes(target, cookie, names):
    """(major opcode -> name, name -> first event code) for `names` the server has.

    Hiding an extension in QueryExtension is not enough on its own: major
    opcodes are stable for the life of the server, so a client that never
    asks can still use one it guessed.  Learning them once at startup lets
    the proxy recognise an extension request -- to refuse it, or to inspect
    its arguments -- without having to have watched this client's own
    QueryExtension go by.

    The *event* base in the same reply is learned here for exactly the same
    reason, and used not to be: the event filter that withholds XkbStateNotify
    and XkbIndicatorStateNotify recognises them by "type == the base XKEYBOARD
    was assigned", and the only place that base came from was a QueryExtension
    reply the client chose to ask for.  A client that skipped the question and
    used the stable opcode -- the very trick the opcode learning above exists
    to defeat -- got the whole XKB event stream: measured, subtypes 2 and 4
    arriving through the proxy exactly as they do direct, which is the ninth
    pass's modifier-state closure and the eleventh's lock-state closure both
    undone by not asking a question.
    """
    sock, endian = _learn_setup(target, cookie)
    if sock is None:
        return {}, {}
    opcodes, events = {}, {}
    for extension in sorted(names):
        raw = extension.encode()
        padded = raw + b"\0" * pad4(len(raw))
        sock.sendall(struct.pack(endian + "BxHH2x", 98,
                                 2 + len(padded) // 4, len(raw)) + padded)
        reply = read_exactly(sock, 32)
        if not reply or reply[0] != 1:
            continue
        extra = struct.unpack(endian + "I", reply[4:8])[0] * 4
        if extra:
            read_exactly(sock, extra)
        if reply[8]:                         # present
            opcodes[reply[9]] = extension
            if reply[10]:                    # first_event; 0 means "no events"
                events[extension] = reply[10]
    return opcodes, events           # the socket stays open: see _learn_setup


def learn_denied_opcodes(target, cookie):
    """Major opcodes held by the denied extensions (see the general helper).
    Their event bases are of no interest: every request in them is refused."""
    return learn_extension_opcodes(target, cookie, KNOWN_DENIED_EXTENSIONS)[0]


# Atoms 1 and 2 are PRIMARY and SECONDARY: predefined, so their ids are
# fixed on every server without anyone interning them.
PREDEFINED_SELECTION_IDS = {"PRIMARY": 1, "SECONDARY": 2}


def learn_atoms(target, cookie, names):
    """name -> server-global atom id, resolved once against the real server.

    Every rule in this file is written in *names* -- CLIPBOARD,
    _NET_WM_STATE, WM_CLASS -- and the wire carries only numbers.  The
    mapping between them used to be a by-product of the client's own
    traffic: the proxy knew a name for an atom only because it had watched
    that client intern it.  A client that comes by an id some other way and
    never asks for the name therefore met a policy that could not recognise
    what it was looking at, and both halves of that failed in the direction
    of the client:

      * gates written as `atom_name(x) == "_NET_WM_STATE"` did not fire, so
        the fullscreen (desktop-spoof) gate was walked past by a window that
        set the property by id -- measured going fullscreen through the
        proxy, while the same request with the name interned was refused;
      * allowlists written as `atom_name(x) in FOREIGN_PROPERTY_ALLOW` did
        not admit, so an ordinary read of _NET_SUPPORTED by id came back
        empty until the same client interned the name.

    So the proxy resolves the names its own policy mentions, here, before any
    client connects, exactly as it already did for the gated selections --
    that fix ("a denylist that fails open on the one value it was meant to
    catch is worse than no lock at all") was this same finding, met once and
    fixed only where it was met.  Atom ids are server-global and stable for
    the life of the server, so one pass is enough.
    """
    resolved = {}
    sock, endian = _learn_setup(target, cookie)
    if sock is None:
        return resolved
    for name in sorted(names):
        raw = name.encode()
        padded = raw + b"\0" * pad4(len(raw))
        # InternAtom with only-if-exists = 0, so the atom is created if the
        # server has not seen it yet; either way we get its stable id.
        sock.sendall(struct.pack(endian + "BBHH2x", 16, 0,
                                 2 + len(padded) // 4, len(raw)) + padded)
        reply = read_exactly(sock, 32)
        if not reply or reply[0] != 1:
            continue
        atom = struct.unpack(endian + "I", reply[8:12])[0]
        if atom:
            resolved[name] = atom
    return resolved                  # the socket stays open: see _learn_setup


def learn_selection_atoms(target, cookie, resolved=None):
    """The server-global atom ids of the gated selections."""
    ids = {atom for name, atom in PREDEFINED_SELECTION_IDS.items()
           if name in GATED_SELECTIONS}
    if resolved is None:
        resolved = learn_atoms(target, cookie, GATED_SELECTIONS)
    ids.update(atom for name, atom in resolved.items()
               if name in GATED_SELECTIONS)
    return ids


def free_display(start=20, stop=100):
    """A display number nothing else is using."""
    for number in range(start, stop):
        if not os.path.exists("/tmp/.X11-unix/X%d" % number):
            return ":%d" % number
    raise SystemExit("no free display number between :%d and :%d"
                     % (start, stop))


def spawn(command, display, xauth, finish):
    """Run the client with the proxy's display, and stop when it stops."""
    env = dict(os.environ, DISPLAY=display, XAUTHORITY=xauth)
    try:
        child = subprocess.Popen(command, env=env)
    except OSError as exc:
        raise SystemExit("cannot run %s: %s" % (command[0], exc))

    def wait():
        child.wait()
        finish()

    threading.Thread(target=wait, daemon=True).start()
    return child


#: How long the prompt waits for the selection's owner to hand over the
#: preview.  The owner is another application and need never answer, so this
#: is a bound on somebody else's behaviour: a prompt that appears with no
#: preview is a nuisance, a prompt that never appears is a hang.
PREVIEW_TIMEOUT = 3


# --- trust domains: starting a proxy, and using one -------------------------
#
# These are two different jobs and the code keeps them apart, because
# conflating them is what makes this kind of thing complicated.
#
#   *Starting* happens once per trust domain and decides everything that
#   matters -- which display, which cookie, which upstream, which gate.  It is
#   an ordinary foreground run of this program under a name, so a terminal, a
#   login script or a systemd user unit can own it, and it lives until it is
#   stopped.  Backgrounding it is not this program's business: `&` is a thing
#   shells already do, and xfilter.bash does it there where it can be read.
#
#   *Using* happens constantly, from every shell and script, and decides
#   nothing: it looks up the display and cookie a name resolves to and puts
#   them in front of one command.
#
# The display is not recorded anywhere: it is *derived* from the name (a hash
# picks where to start looking) and confirmed by asking the server there
# whether it takes this domain's cookie.  That test is what makes a collision
# safe -- two names that start looking in the same place do not merge into one
# proxy, because the second one is refused and moves on.  Sharing a proxy is
# sharing everything behind it, so a silent merge is the one outcome that must
# be impossible.

#: The display numbers a derived domain may live on.
DOMAIN_FIRST, DOMAIN_LAST = 20, 79


def domain_root():
    """Where a user's domain files live: cookie and pid, one pair per domain.

    $XDG_RUNTIME_DIR when there is one -- per-user, on tmpfs, cleared at
    logout, which is the right lifetime for a display that dies with the
    session -- and the temp directory otherwise.
    """
    base = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
    root = os.path.join(base, "xfilter-%d" % os.getuid())
    os.makedirs(root, mode=0o700, exist_ok=True)
    return root


def domain_key(name):
    """A filename for a domain, that two domains cannot share.

    Anything awkward is replaced, and a hash of the original is appended when
    that replacement lost information: `me@host` and `me/host` must not become
    one set of files, because one set of files would mean one proxy.
    """
    safe = re.sub(r"[^A-Za-z0-9._@-]", "_", name)
    if safe != name or len(safe) > 64:
        safe = "%s-%s" % (safe[:64],
                          hashlib.sha1(name.encode()).hexdigest()[:8])
    return safe


def domain_auth(name):
    return os.path.join(domain_root(), domain_key(name) + ".auth")


def domain_pid_file(name):
    return os.path.join(domain_root(), domain_key(name) + ".pid")


def domain_displays(name):
    """Display numbers to try for a domain, best first.

    A hash spreads domains over the range so two of them usually do not
    contend, and the walk from there means a busy display simply costs the
    next number rather than a failure.
    """
    span = DOMAIN_LAST - DOMAIN_FIRST + 1
    first = int(hashlib.sha1(name.encode()).hexdigest()[:8], 16) % span
    return [DOMAIN_FIRST + (first + step) % span for step in range(span)]


def domain_socket(number):
    return "/tmp/.X11-unix/X%d" % number


def domain_running(name):
    """The display this domain's proxy is on, or None if it is not up.

    Only the numbers this domain has a cookie for are worth asking about, and
    each one is settled by a real handshake: a socket file left behind by a
    dead proxy refuses the connection, and a *live* proxy belonging to some
    other domain refuses the cookie.  Nothing here trusts a file's word for
    it.
    """
    auth = domain_auth(name)
    numbers = sorted({int(entry[2]) for entry in read_xauth(auth)
                      if entry[2].isdigit()})
    for number in numbers:
        display = ":%d" % number
        if not os.path.exists(domain_socket(number)):
            continue
        try:
            cookie = cookie_for(auth, display)
        except SystemExit:
            continue
        try:
            if accepted_by_upstream(parse_display(display), cookie):
                return display
        except (OSError, SystemExit):
            # Anything that is not a clean "yes" means not running, and the
            # noisy case is a proxy shutting down while we ask: it accepts the
            # connection and then dies, which arrives here as a reset rather
            # than as a refusal.  --stop polls this in a loop, so it is the
            # normal way a stopping proxy is seen to have stopped.
            continue
    return None


def domain_free_display(name):
    """The first display number nothing is using, in this domain's order."""
    for number in domain_displays(name):
        if not os.path.exists(domain_socket(number)):
            return ":%d" % number
    raise SystemExit("no free display between :%d and :%d"
                     % (DOMAIN_FIRST, DOMAIN_LAST))


def domain_environment(name):
    """DISPLAY and XAUTHORITY for a running domain, or a message saying how
    to start it.  Every use of a domain comes through here."""
    display = domain_running(name)
    if not display:
        raise SystemExit(
            "no filter is running for %s.\n"
            "Start one with:  xfilter.py --domain %s --gate ask" % (name, name))
    return {"DISPLAY": display, "XAUTHORITY": domain_auth(name)}


def use_domain(name, command):
    """--use: run one command against a domain's display.

    Scoped to the command on purpose.  Exporting a domain into a *shell*
    leaves it there after you have forgotten, and the next thing you start in
    that shell silently joins a trust domain it has nothing to do with.
    """
    env = dict(os.environ, **domain_environment(name))
    try:
        child = subprocess.Popen(command, env=env)
    except OSError as exc:
        raise SystemExit("cannot run %s: %s" % (command[0], exc))
    try:
        raise SystemExit(child.wait())
    except KeyboardInterrupt:
        child.terminate()
        raise SystemExit(child.wait())


def print_domain_environment(name):
    """--env: the same thing, for `eval` in a script.

    stdout is the machine's and stderr is the person's, so this prints the two
    lines and nothing else.  The scope rule from use_domain applies to whoever
    evals it: everything after it belongs to that domain.
    """
    for key, value in sorted(domain_environment(name).items()):
        print("export %s=%s" % (key, shlex.quote(value)))


#: How often the proxy checks that the display it forwards to is still there,
#: and how many misses in a row it takes to believe it.  A poll rather than a
#: watch on the anchor connection, because focus_window reads that socket and
#: a second reader would eat its replies.
UPSTREAM_POLL, UPSTREAM_MISSES = 5, 3


def watch_upstream(target, display, finish):
    """Stop when the display we forward to goes away.

    Two reasons, and the second is the one that matters.

    A proxy whose upstream is gone serves nothing -- every client it accepts
    fails at the handshake -- so it is a display number and a pid pretending
    to be a service.  With `--domain` it is long-lived, so without this an X
    session ending would leave one behind on every logout, and the next login
    would start another beside it.

    And the server's *vocabulary* is what the policy is written against: atom
    ids and extension opcodes are learned once, from that server, and are
    stable only for its life.  If a new server comes up on the same display,
    every rule keyed on those numbers would be judging a stranger's ids --
    the thirteenth pass's finding, arriving by a different road.  Exiting, and
    being started again against the new server, is the only honest answer.
    """
    misses = 0
    while True:
        time.sleep(UPSTREAM_POLL)
        try:
            connect_upstream(target).close()
            misses = 0
        except OSError:
            misses += 1
            if misses >= UPSTREAM_MISSES:
                print("the upstream display %s is gone; exiting" % display,
                      file=sys.stderr)
                finish()
                return


def list_domains():
    """What is running, for the user who has forgotten what they started."""
    root = domain_root()
    rows = []
    for entry in sorted(os.listdir(root)):
        if not entry.endswith(".pid"):
            continue
        path = os.path.join(root, entry)
        try:
            with open(path) as handle:
                pid = int(handle.readline().strip())
                name = handle.readline().strip() or entry[:-4]
        except (OSError, ValueError):
            continue
        display = domain_running(name)
        rows.append((name, display or "-", pid,
                     "yes" if display else "no"))
    if not rows:
        print("no filtered domains are running")
        return
    print("%-30s %-9s %-8s %s" % ("domain", "display", "pid", "serving"))
    for row in rows:
        print("%-30s %-9s %-8d %s" % row)


def stop_domain(name):
    pid_file = domain_pid_file(name)
    try:
        with open(pid_file) as handle:
            pid = int(handle.readline().strip())
    except (OSError, ValueError):
        raise SystemExit("no filter is recorded for %s" % name)
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        print("it was not running (%s); cleaning up" % exc, file=sys.stderr)
    for _ in range(40):
        if not domain_running(name):
            break
        time.sleep(0.25)
    for path in (pid_file, domain_auth(name)):
        try:
            os.unlink(path)
        except OSError:
            pass
    print("stopped the filter for %s" % name)


def fetch_selection(selection, timeout=PREVIEW_TIMEOUT):
    """What is actually in the selection right now, for the prompt.

    Read over the GTK connection the prompt is already using rather than by
    running xclip.  --gate ask needs GTK regardless, and that connection is
    to the real display, which is where the selection lives and deliberately
    not through our own filtered one.  Shelling out made the preview depend
    on a package nobody was told to install, and when it was missing the
    dialog said the owner had offered nothing readable -- a different fact,
    and the wrong one to show somebody deciding whether to allow a paste.

    Anything that is not text comes back empty, which is the same answer the
    old path gave and is honest: an image is not something this dialog can
    show, and the caller says so.
    """
    from gi.repository import Gtk, Gdk, GLib

    clipboard = Gtk.Clipboard.get(Gdk.Atom.intern(selection, False))
    loop, box = GLib.MainLoop(), {"text": "", "done": False, "timer": None}

    def finished():
        box["done"] = True
        if loop.is_running():
            loop.quit()

    def arrived(_clipboard, text):
        box["text"] = text or ""
        finished()

    def expired():
        box["timer"] = None       # already gone: do not remove it twice
        finished()
        return False

    # The callback can fire before the loop starts -- when we own the
    # selection ourselves the answer is immediate -- and quitting a loop that
    # has not run leaves it running forever, so the flag is what decides.
    clipboard.request_text(arrived)
    if not box["done"]:
        box["timer"] = GLib.timeout_add(int(timeout * 1000), expired)
        loop.run()
    if box["timer"] is not None:
        GLib.source_remove(box["timer"])
    return box["text"]


def bring_to_front(dialog, first=False):
    """Put the prompt where the user will actually see it.

    Three different things can bury it, so three different things are asked:

      * **A window manager's focus-stealing prevention.**  A map from an
        application the user has not just interacted with is deliberately not
        given the focus -- the window is marked "wants attention" and left
        where it is.  The answer is a real X server timestamp: with one,
        present_with_time is a request the window manager will honour.
      * **A window manager's stacking.**  keep-above, sticky and the urgency
        hint are set once on the dialog; they are properties, not actions.
      * **No window manager at all**, which is the case inside a bare Xephyr
        -- the shape this project's own live rig has.  Then every hint above
        means nothing, because nothing is reading them, and the only thing
        that raises a window is XRaiseWindow.  So the prompt raises itself,
        and keeps doing it on each countdown tick: a client that maps a
        window afterwards must not be able to bury the decision it is the
        subject of.

    The timestamp is fetched only on the first call.  It is a round trip to
    the server (a zero-length property append, then its PropertyNotify), and
    the tick that follows only needs to restack.
    """
    window = dialog.get_window()
    if window is None:                       # not realised yet: nothing to do
        return
    window.raise_()
    if not first:
        return
    try:
        import gi
        gi.require_version("GdkX11", "3.0")
        from gi.repository import GdkX11
        stamp = GdkX11.x11_get_server_time(window)
    except Exception:                        # not X11, or no GdkX11 typelib
        stamp = 0
    if stamp:
        dialog.present_with_time(stamp)
    else:
        dialog.present()


class Gate:
    """Holds a paste until the user rules on it.

    The connection thread blocks in decide() while the GTK loop in the main
    thread shows the prompt; the X client is simply waiting for its
    SelectionNotify, which is what pasting looks like anyway.  Decisions
    are remembered per application and selection for a while, because
    applications ask repeatedly -- an IDE was seen converting CLIPBOARD
    four times just starting up, and four dialogs would be intolerable.
    """

    #: A refusal is remembered this long.  An application that reads the
    #: clipboard in a loop must not be able to raise a dialog per attempt,
    #: so saying no once buys quiet -- briefly, so an accidental Deny does
    #: not lock you out for the afternoon.
    QUIET_AFTER_DENY = 30

    #: Prompts waiting at once.  Past this, further requests are refused
    #: without asking: a queue of dialogs is not a decision, it is a flood.
    MAX_PENDING = 2

    def __init__(self, timeout, remember):
        self.timeout = timeout
        self.remember = remember
        self.requests = queue.Queue()
        self.decisions = {}
        self.inflight = {}
        self.lock = threading.Lock()

    def decide(self, token, identity, selection, target, peer, action="read"):
        # Key on the connection token, not the claimed identity: the name is
        # the client's own testimony, so keying decisions on it let a second
        # application inherit a grant by adopting a name already allowed, and
        # let a hostile one label its prompt however it liked.
        # The token is one per connection; the claimed name and the
        # unforgeable peer credentials are carried along only for the dialog.
        # The action is part of the key too: being allowed to read the
        # clipboard is not permission to become it.
        key = (token, selection, action)
        now = time.time()
        with self.lock:
            remembered = self.decisions.get(key)
            if remembered and remembered[1] > now:
                return remembered[0]

            waiting = self.inflight.get(key)
            if waiting is not None:
                # The same connection asking again while its first request is
                # still on screen: one dialog, one answer.
                answer, answered = waiting
                mine = False
            elif self.requests.qsize() >= self.MAX_PENDING:
                self.decisions[key] = (False, now + self.QUIET_AFTER_DENY)
                return False
            else:
                answer, answered = {}, threading.Event()
                self.inflight[key] = (answer, answered)
                mine = True

        if mine:
            self.requests.put((identity, selection, target, peer, action,
                               answer, answered))
        answered.wait(self.timeout + 5)
        allow = answer.get("allow", False)

        with self.lock:
            self.inflight.pop(key, None)
            if allow and answer.get("remember"):
                self.decisions[key] = (allow, time.time() + self.remember)
            elif not allow:
                self.decisions[key] = (False,
                                       time.time() + self.QUIET_AFTER_DENY)
        return allow

    # -- the GTK side, main thread only ------------------------------------

    def pump(self):
        """Take one pending decision to the user.  Called from the main loop."""
        try:
            request = self.requests.get_nowait()
        except queue.Empty:
            return True
        try:
            self.ask(*request)
        except Exception as exc:                 # never wedge the main loop
            print("prompt failed (%s); denying" % exc, file=sys.stderr)
            request[5]["allow"] = False
            request[6].set()
        return True

    def ask(self, identity, selection, target, peer, action, answer, answered):
        from gi.repository import Gdk, Gtk, GLib

        owning = action == "own"
        fullscreen = action == "fullscreen"
        keyboard = action == "keyboard"
        title = ("Fullscreen request" if fullscreen
                 else "Keyboard request" if keyboard
                 else "Clipboard ownership request" if owning
                 else "Clipboard request")
        dialog = Gtk.Dialog(title=title, modal=False)
        dialog.set_keep_above(True)
        # Shown on every virtual desktop: the prompt denies on a countdown, so
        # one that opened on the desktop the user has just left is a decision
        # taken by default rather than by them.
        dialog.stick()
        dialog.set_urgency_hint(True)
        dialog.add_button("Deny", 0)
        dialog.add_button("Allow once", 1)
        dialog.add_button("Allow for a while", 2)

        # x11_get_server_time works by appending to a property and waiting
        # for the notification, so the window has to be listening for one.
        dialog.add_events(Gdk.EventMask.PROPERTY_CHANGE_MASK)
        box = dialog.get_content_area()
        box.set_spacing(8)
        box.set_border_width(12)
        # The clipboard prompts show the selection's current contents; the
        # fullscreen prompt has nothing to fetch.
        value = "" if fullscreen or keyboard else fetch_selection(selection)
        heading = Gtk.Label(xalign=0)
        # The bold name is the client's own claim about itself and can say
        # anything; the peer line underneath is what the socket reports and
        # the client cannot forge.
        if fullscreen:
            # Taking the whole screen with a borderless window is how a remote
            # client can paint a fake desktop or login prompt over yours: what
            # you type into it goes to it.  Deny leaves it a normal, framed
            # window instead.
            what = ("wants to take over the whole screen with a borderless "
                    "window\n<i>a remote client doing this could spoof a login "
                    "prompt; denying leaves it a normal framed window</i>")
        elif keyboard:
            # A keyboard grab is what a menu takes so that arrow keys reach it
            # -- and while it is held, every key you press goes to this client
            # whatever you think you are typing into.
            what = ("wants to grab the keyboard\n<i>while it holds one, "
                    "everything you type goes to it, whatever window you are "
                    "typing into; menus in this application need it</i>")
        elif owning:
            # Taking ownership is not reading: what is shown below is what the
            # user currently has copied and would lose, and afterwards every
            # paste on the desktop is answered by this client.
            what = ("wants to take over %s\n"
                    "<i>every later paste would come from it, replacing:</i>"
                    % selection)
        else:
            what = "wants to read %s (%d characters)" % (selection, len(value))
        heading.set_markup(
            "<b>%s</b> <i>(self-reported)</i>\n%s"
            "\n<small>connection: %s</small>"
            % (GLib.markup_escape_text(identity), what,
               GLib.markup_escape_text(peer)))
        box.add(heading)

        if not (fullscreen or keyboard):
            view = Gtk.TextView(editable=False, cursor_visible=False,
                                wrap_mode=Gtk.WrapMode.WORD)
            view.get_buffer().set_text(
                value[:2000] or ("(nothing is on the clipboard now)" if owning
                                 else "(the owner offered nothing readable)"))
            scroll = Gtk.ScrolledWindow(min_content_height=160)
            scroll.add(view)
            box.add(scroll)

        countdown = Gtk.Label(xalign=0)
        box.add(countdown)
        dialog.show_all()

        deadline = time.time() + self.timeout
        def tick():
            left = int(deadline - time.time())
            if left <= 0:
                dialog.response(0)
                return False
            countdown.set_text("denied automatically in %ds" % left)
            bring_to_front(dialog)
            return True
        tick()
        GLib.timeout_add(500, tick)
        bring_to_front(dialog, first=True)

        choice = dialog.run()
        dialog.destroy()
        answer["allow"] = choice in (1, 2)
        answer["remember"] = choice == 2
        answered.set()




class PolicyProfile(Profile):
    """Profile plus a record of what the policy did, or would have done."""

    def __init__(self):
        super().__init__()
        self.pastes = set()
        # The enforcing proxy keeps no per-request counters -- the operations
        # log is the whole record.  first_seen holds one entry per distinct
        # operation, the first time it was judged: who asked, and what the
        # policy did.  log_file, if set by --log, gets a copy of each new
        # line and the exit report.
        self.first_seen = {}      # key -> (identity, peer, passed, reason)
        self.log_file = None
        self.gate_hinted = False  # the --gate hint is offered once per run
        self.focus_oracle_reported = False   # ...and the lost-focus warning
        # The application's own windows, as the policy understands them.
        #
        # This is *profile* state, not connection state, and that is the
        # twelfth pass's finding: "own" has always been a fact about the
        # application rather than the connection -- is_foreign() answers from
        # the profile's id ranges, so a window created on one connection is not
        # foreign to the next -- while the model of those windows lived on the
        # connection that made them.  Two protections read that model (the
        # QueryPointer position bound and the fullscreen-overlay gate), so
        # doing the two halves of an operation on two connections walked around
        # both: measured, connection B read the global pointer position through
        # connection A's window, and resized A's small override-redirect window
        # to cover the screen without the gate firing.
        #
        # Each entry is [width, height, override, mapped, parent].  `mapped`
        # exists because an unmapped window is not somewhere the pointer can
        # be, and a client that never maps one is holding a measuring stick,
        # not a window.  `parent` exists so a destroyed window can be forgotten
        # with its subtree: the model used to be write-only, growing for the
        # life of the connection whatever the client destroyed, which both
        # leaked memory and left stale sizes behind ids the server had freed.
        self.windows = {}         # window id -> [w, h, override, mapped, parent, root]
        self.children = {}        # parent id -> set of tracked child ids

    def note_window(self, window, parent, width, height, override, root=0):
        """A window the application just created.

        `root` is the screen it lives on -- a window is "fullscreen" only
        against the screen it is actually on, and a server with two screens is
        an ordinary desktop.
        """
        with self.lock:
            self._forget(window)
            self.windows[window] = [width, height, override, False, parent,
                                    root]
            self.children.setdefault(parent, set()).add(window)

    def note_geometry(self, window, width, height):
        with self.lock:
            state = self.windows.get(window)
            if state is not None:
                state[0], state[1] = width, height

    def note_override(self, window, override):
        with self.lock:
            state = self.windows.get(window)
            if state is not None:
                state[2] = bool(override)

    def note_mapped(self, window, mapped, subwindows=False):
        """Map or unmap a window, or (subwindows) its tracked children."""
        with self.lock:
            targets = (list(self.children.get(window, ())) if subwindows
                       else [window])
            for target in targets:
                state = self.windows.get(target)
                if state is not None:
                    state[3] = bool(mapped)

    def forget_window(self, window, subwindows=False):
        """Drop a destroyed window, or (subwindows) its children, and their
        descendants: the server has freed them, and so must the model."""
        with self.lock:
            if subwindows:
                for child in list(self.children.get(window, ())):
                    self._forget(child)
            else:
                self._forget(window)

    def reparent_window(self, window, parent):
        with self.lock:
            state = self.windows.get(window)
            if state is None:
                return
            self.children.get(state[4], set()).discard(window)
            state[4] = parent
            self.children.setdefault(parent, set()).add(window)

    def _forget(self, window):
        """Caller holds the lock.  Drops the window and everything under it."""
        stack = [window]
        while stack:
            current = stack.pop()
            for child in self.children.pop(current, ()):
                stack.append(child)
            state = self.windows.pop(current, None)
            if state is not None:
                self.children.get(state[4], set()).discard(current)

    def override_area_by_screen(self):
        """Total area of the application's mapped override-redirect windows.

        The fullscreen gate asks whether *a* window covers the screen, and a
        fake desktop does not have to be one window: four override-redirect
        windows, each half the screen's width and half its height, are none of
        them fullscreen and together they are the whole screen.  Measured --
        through the proxy, with a window manager running, four such windows
        turned every quadrant of the real screen the attacker's colour, and the
        operation log said only `CreateWindow allowed`, `MapWindow allowed`.
        So the gate needs a number that adds up, and this is it.

        Area rather than a union of rectangles: overlapping windows are counted
        twice, so this over-estimates coverage and can only gate early, never
        late.  Menus and tooltips -- the override-redirect windows a real
        application makes -- are small, and a few of them come nowhere near the
        threshold.
        """
        totals = {}
        with self.lock:
            for state in self.windows.values():
                if state[2] and state[3]:
                    totals[state[5]] = totals.get(state[5], 0) \
                        + state[0] * state[1]
        return totals

    def window_state(self, window):
        """(width, height, override, mapped, parent, root) for a tracked
        window, else None."""
        with self.lock:
            state = self.windows.get(window)
            return None if state is None else tuple(state)

    def note_allowed_paste(self, identity, selection):
        with self.lock:
            self.pastes.add((selection, identity))

    def note_first_seen(self, key, identity, peer, passed, reason):
        """Record an operation the first time it is seen; True if it is new.

        Called only when a connection meets an operation it has not met
        before, so the string key and the process name are built once per
        new operation, never per request.
        """
        with self.lock:
            if key in self.first_seen:
                return False
            self.first_seen[key] = (identity, peer, passed, reason)
        return True

    def note_focus_oracle_lost(self):
        """Say once that the focus oracle is gone, because the policy is now
        degraded and silence about that is how a security tool lies.

        Twenty-eighth pass.  The focus question is asked on the proxy's own
        upstream connection; if that connection is missing or has died, the
        answer is "I don't know", and a client holding a keyboard grab is then
        withheld its keys rather than handed everybody's.  That is the safe
        direction, but it is also a *changed* behaviour the operator has to be
        able to see -- a menu that stops taking arrow keys has a cause, and it
        should be findable in the log rather than mysterious.
        """
        with self.lock:
            if self.focus_oracle_reported:
                return False
            self.focus_oracle_reported = True
        line = ("the focus oracle is unavailable: keystrokes are being withheld "
                "from clients holding a keyboard grab, because the proxy can no "
                "longer tell whose window is focused")
        print(line, file=sys.stderr)
        self.log_line(line)
        return True

    def note_gate_hint(self):
        """True the first time the clipboard gate refuses under --gate deny."""
        with self.lock:
            if self.gate_hinted:
                return False
            self.gate_hinted = True
        return True

    def log_line(self, text):
        """Write one line to the --log file, if there is one."""
        handle = self.log_file
        if handle is not None:
            with self.lock:
                try:
                    handle.write(text + "\n")
                except (OSError, ValueError):
                    pass

    def dump(self, stream=sys.stdout, enforcing=False):
        with self.lock:
            first_seen = dict(self.first_seen)
            pastes = sorted(self.pastes)
            connections = self.connections
        allowed = sorted(k for k, v in first_seen.items() if v[2])
        blocked = sorted((k, v) for k, v in first_seen.items() if not v[2])
        # A name can appear in both lists: allowed on the client's own window,
        # blocked on a foreign one.  That pairing is the interesting signal,
        # so it is reported rather than collapsed.
        both = {k[0] for k in allowed} & {k[0] for k, _ in blocked}
        print("\n%d connections, %d distinct operations\n"
              % (connections, len(first_seen)), file=stream)
        if allowed:
            print("operations allowed:\n", file=stream)
            for key in allowed:
                print("    %s%s" % (key[0],
                                    "  (also blocked, see below)"
                                    if key[0] in both else ""), file=stream)
        heading = "operations blocked" if enforcing \
            else "operations that would be blocked (dry run)"
        if blocked:
            print("\n%s:\n" % heading, file=stream)
            print("    %-40s %-28s %s" % ("operation", "rule", "first from"),
                  file=stream)
            for key, (identity, peer, _passed, reason) in blocked:
                print("    %-40s %-28s %s [%s]"
                      % (key[0], reason or "", identity, peer), file=stream)
        else:
            print("\nnothing was blocked", file=stream)
        if any(v[3] in (GATE_REFUSED, GATE_OWNER_REFUSED)
               for v in first_seen.values() if not v[2]):
            print("\n%s" % GATE_HINT, file=stream)
        if pastes:
            print("\npastes you allowed:\n", file=stream)
            for selection, identity in pastes:
                print("    %s -> %s" % (selection, identity), file=stream)
        stream.flush()


class PolicyConnection(Connection):
    """A connection whose requests are judged before being forwarded."""

    gate = None
    gate_mode = "deny"
    #: Server-global atom ids of the gated selections, resolved at startup so
    #: the gate can compare by id and not just by a name it happened to see
    #: interned.
    gated_selection_ids = frozenset()
    #: major opcode -> name for every allowlisted (and therefore inspected)
    #: extension, learned at startup so we recognise them without waiting for
    #: this client's own QueryExtension.  An opcode in neither this map nor the
    #: denied set, and not since learned from a QueryExtension reply, is blocked.
    extension_opcodes = {}
    #: Whether to print a one-line alert the first time an operation appears.
    alert_new = True
    _token_lock = threading.Lock()
    _token_counter = 0

    def __init__(self, *args, enforce=False, denied_opcodes=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.enforce = enforce
        # The relay recognises BigReqEnable by its major opcode, and used to
        # learn that opcode only from this client's own QueryExtension reply.
        # A client that used the (stable, guessable) opcode without asking
        # therefore enabled big requests on the *server* while the relay went
        # on believing the zero-length form illegal, and dropped the link at
        # the first one.  That failure was closed rather than open, but it is
        # the same shape as the two holes this pass fixed, so it is fixed the
        # same way: the proxy knows the opcode itself.
        for opcode, name in self.extension_opcodes.items():
            if name == "BIG-REQUESTS":
                self.bigreq_opcode = opcode
        self.substitutions = {}       # sequence -> reply bytes
        self.reply_scrubs = {}        # sequence -> byte ranges to blank in the reply
        self.reply_foreign = {}       # sequence -> window-field offsets to blank if foreign
        self.reply_pointer = {}       # sequence -> (own-window size, layout) to bound a pointer reply
        self.reply_leds = set()       # sequences whose feedback list has its LED state blanked
        self.seen = set()             # operation keys already logged on this connection
        with PolicyConnection._token_lock:
            PolicyConnection._token_counter += 1
            self.conn_token = PolicyConnection._token_counter
        self.denied_opcodes = set(denied_opcodes)   # hidden extensions
        self.query_denied = {}        # sequence -> True, hide this extension
        self.gated = {}               # (requestor, property) -> selection
        # Two capabilities the policy grants from traffic it watched: a
        # SelectionRequest naming this client means somebody asked it for a
        # selection, so it may answer -- write that property on that window,
        # and send the SelectionNotify.  They are *timed*, not permanent.  A
        # transfer takes a moment (an INCR one a little longer); a grant that
        # never expires is a standing capability over another application's
        # window earned by one paste, and it exempts that window from the EV-3
        # rule that withholds PropertyNotify for a property this client may not
        # read -- so a single copy-out bought a permanent property-change
        # monitor on the window that asked for it.  Each is a deadline.
        self.selection_requests = {}   # (window, property) -> expiry
        self.selection_requestors = {}  # window -> expiry
        # Twenty-eighth pass.  Whether this connection is holding an active
        # keyboard grab, in any of its three spellings.  It is the one state
        # that distinguishes "this client cannot be receiving somebody else's
        # keystrokes" from "this client is receiving all of them", and the
        # focus rule needs it for the case where the focus itself cannot be
        # read -- see _focus_is_ours.
        self.keyboard_grabbed = False
        self.identity = {}            # class / name / pid / host
        self.listings = set()         # sequences of ListExtensions requests
        self.root = 0
        self.roots = set()            # every screen's root window
        self.root_depth = 24          # first screen's depth
        self.root_visual = 0          # first screen's root visual id
        self.screen_width = 0         # first screen's width in pixels
        self.screen_height = 0        # first screen's height in pixels
        self.screen_size = {}         # root window -> that screen's size
        # The model of the application's own windows -- their size, whether
        # they are override-redirect, whether they are mapped -- lives on the
        # *profile*, shared by every connection of the application, because
        # that is the scope at which "own" is defined (PolicyProfile.windows).
        # It used to live here, per connection, which let a second connection
        # of the same application read the pointer position and assemble a
        # fullscreen overlay past gates that could not see what the first had
        # done.

    # -- helpers -----------------------------------------------------------

    def note_identity(self, body):
        """Read WM_CLASS and friends out of a ChangeProperty going past."""
        atom = self.atom_name(self.word(body, 4))
        field = IDENTITY_PROPERTIES.get(atom)
        if field is None or len(body) < 20:
            return
        # Offsets are into the body, which has already had the 4-byte request
        # header stripped: window 0, property 4, type 8, format 12, length 16,
        # data 20.  (Counting 24 -- the offset from the start of the request
        # *including* its header -- landed four bytes late and ate the first
        # four characters of every WM_CLASS.)  The length field counts items in
        # format units, not bytes, so a 32-bit _NET_WM_PID has length 1.
        format_bits = body[12]
        if format_bits not in (8, 16, 32):
            return
        length = self.word(body, 16) * (format_bits // 8)
        raw = body[20:20 + length]
        if field == "pid":
            if len(raw) >= 4:
                value = str(struct.unpack_from(self.endian + "I", raw, 0)[0])
            else:
                return
        else:
            value = raw.split(b"\0")[0].decode("latin-1", "replace")
        if not value:
            return
        with self.lock:
            self.identity[field] = value

    def describe(self):
        """A human label for whoever is on this connection.

        Every field here is the client's own testimony -- WM_CLASS, WM_NAME,
        _NET_WM_PID, WM_CLIENT_MACHINE, all properties it set on its own
        window -- and this string is printed to the operator's terminal, appended
        to the --log file, and shown in bold in the gate prompt.  So it is put
        through printable() on the way out: a newline in a WM_CLASS forged a
        whole line of the operation log (measured: a client called itself
        "xterm\\nnew operation: core:GetImage  allowed  trusted desktop app
        [local pid 1, uid 0]" and that line duly appeared, three times), an
        escape sequence rewrote the terminal it was printed to, and three
        hundred characters of padding pushed the real lines out of view.  The
        stored value is untouched; only what is *said* about it is cleaned.
        """
        with self.lock:
            known = dict(self.identity)
        if known.get("class") and known.get("pid"):
            return printable("%s (pid %s on %s)"
                             % (known["class"], known["pid"],
                                known.get("host", "?")))
        for field in ("class", "name", "pid"):
            if known.get(field):
                return printable(known[field])
        return "unidentified client"

    def atom_name(self, atom):
        with self.profile.lock:
            return self.profile.atoms.get(atom)

    def word(self, body, offset):
        return struct.unpack_from(self.endian + "I", body, offset)[0]

    def reply(self, sequence, data=b"", first=0):
        """A 32-byte reply: type 1, one free byte, sequence, length 0."""
        head = struct.pack(self.endian + "BBHI", 1, first, sequence, 0)
        return head + data.ljust(24, b"\0")

    def error(self, sequence, code, opcode, minor):
        return struct.pack(self.endian + "BBHIHBx", 0, code, sequence, 0,
                           minor, opcode) + b"\0" * 20

    def _empty_keymap(self, sequence):
        """A QueryKeymap reply with no key down: 32 zero bytes of key state.

        The reply length is 2 (eight words past the 32-byte base), so the
        key bitmap is 24 bytes in the fixed reply plus 8 more -- 32 in all,
        every one zero.
        """
        return struct.pack(self.endian + "BBHI", 1, 0, sequence, 2) + b"\0" * 32

    def _blank_geometry(self, sequence):
        """A GetGeometry reply for a window the client may not measure.

        Shaped like a real answer -- the screen's root and depth, a zero-sized
        rectangle at the origin -- rather than an error, because an error kills
        simple Xlib clients and a client asking this of somebody else's window
        is enumerating, not rendering.
        """
        data = struct.pack(self.endian + "IhhHHH2x", self.root, 0, 0, 0, 0, 0)
        return self.reply(sequence, data, first=self.root_depth)

    def _blank_attributes(self, sequence):
        """A GetWindowAttributes reply that describes nothing.

        An InputOutput window, unmapped, with no event masks and no colormap.
        The reply is 44 bytes -- three words past the 32-byte base -- so the
        length field is 3.

        The visual is the screen's root visual rather than 0, and that is not
        cosmetic.  Xlib does not hand the client the id: XGetWindowAttributes
        resolves it through _XVIDtoVisual, which answers NULL for an id the
        screen does not list -- and 0 is never listed.  It still reports
        success, so the client gets a NULL Visual* it did not check, and the
        next call that touches it (XVisualIDFromVisual, say) dereferences NULL
        and takes the process down.  A blank answer has to stay a *coherent*
        answer: an InputOutput window on the root visual is one, an
        InputOutput window on no visual at all is not.
        """
        head = struct.pack(self.endian + "BBHI", 1, 0, sequence, 3)
        return head + struct.pack(self.endian + "IHBBIIBBBBIIIH2x",
                                  self.root_visual, 1, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0)

    def peer_label(self):
        """An unforgeable word about who is connected, unlike the claimed name."""
        if self.peer_pid is not None:
            return "local pid %s, uid %s" % (self.peer_pid, self.peer_uid)
        return "remote client, no local process credentials"

    def configures_foreign_sibling(self, body):
        """True if a ConfigureWindow stacks against a window we do not own.

        The sibling is optional and lives in the value list, whose entries
        appear in value-mask bit order -- x, y, width, height, border-width,
        sibling, stack-mode -- so its offset depends on how many lower bits
        are set.
        """
        mask = struct.unpack_from(self.endian + "H", body, 4)[0]
        if not mask & CW_SIBLING:
            return False
        offset = 8 + 4 * bin(mask & (CW_SIBLING - 1)).count("1")
        if len(body) < offset + 4:
            return False
        return self.is_foreign(self.word(body, offset))

    #: How long a selection grant lives *without being used*.  Long enough
    #: for a transfer the user asked for, including an INCR one with a slow
    #: requestor; short enough that it is an answer to a request rather than a
    #: standing permission.  The clock is reset by renew_selection_grant every
    #: time the requestor takes another chunk, so this bounds an *idle* grant,
    #: not the length of a transfer -- see that method for why the difference
    #: matters and why the reset cannot be driven by the client.
    SELECTION_GRANT_SECONDS = 60

    def grant_selection(self, window, prop):
        """Record that this client may answer a selection request, briefly."""
        deadline = time.time() + self.SELECTION_GRANT_SECONDS
        with self.lock:
            self.selection_requests[(window, prop)] = deadline
            self.selection_requestors[window] = deadline
            # Expired grants are dropped as they are noticed rather than on a
            # timer: nothing else needs a thread, and the tables only grow
            # while requests keep arriving.
            now = time.time()
            for table in (self.selection_requests, self.selection_requestors):
                for key in [k for k, when in table.items() if when <= now]:
                    del table[key]

    def granted(self, table, key):
        """True while a grant recorded by grant_selection is still live."""
        with self.lock:
            return table.get(key, 0) > time.time()

    def renew_selection_grant(self, window, prop):
        """Restart the clock on a grant that is still being used.

        Twenty-sixth pass.  A grant was minted once, at the SelectionRequest,
        and never refreshed, so sixty seconds was a ceiling on the whole
        transfer rather than on an idle one.  A big clipboard payload does not
        cross in one request: the owner answers with a type of INCR and then
        feeds the data in chunk by chunk, each chunk written into the
        requestor's window and each one waiting for the requestor to consume
        the last.  That takes as long as the requestor is slow, and when the
        grant died mid-transfer the writes were dropped and both sides waited
        for each other for ever.  Measured: a nineteen-megabyte paste to a
        requestor taking five seconds a chunk stopped dead after twelve of
        nineteen chunks -- exactly sixty seconds in -- where the same transfer
        with no proxy in the path completed.

        What resets the clock is deliberately *not* the client's own writes,
        which would let it hold a grant open by itself for ever.  It is the
        requestor consuming a chunk -- a server-generated PropertyNotify from
        the far side, which the filtered client cannot forge (a SendEvent one
        arrives with the 0x80 bit set, and patch_event checks it there for the
        same reason it checks it on SelectionRequest).  So the grant lives
        while the other end keeps asking for more and dies sixty seconds after
        it stops.

        A dead grant is never revived: this only extends one that is still
        live, so there is no path here from "no permission" to "permission".
        """
        now = time.time()
        with self.lock:
            if self.selection_requestors.get(window, 0) <= now:
                return False
            deadline = now + self.SELECTION_GRANT_SECONDS
            self.selection_requestors[window] = deadline
            if (window, prop) in self.selection_requests:
                self.selection_requests[(window, prop)] = deadline
            return True

    def is_gated_selection(self, atom):
        """True for CLIPBOARD/PRIMARY/SECONDARY, by id or by known name.

        The id set is the real gate; the name check still
        catches a selection interned through us whose id we did not resolve
        at startup -- an extra GATED_SELECTIONS entry, say.
        """
        return (atom in self.gated_selection_ids
                or self.atom_name(atom) in GATED_SELECTIONS)

    def find_root(self, setup_body):
        """The screens' root windows, from the setup reply.

        handshake() hands us the setup reply with its 8-byte header already
        stripped, so the offsets here are into the body: vendor length at
        16, screen count at 20, format count at 21, and the first SCREEN at
        32 + vendor + padding + 8 per pixmap format.  (Reading them as if the
        header were still present landed eight bytes late and left self.root
        at 0.)

        self.root -- the first screen's -- answers empty QueryTree replies.
        self.roots is every screen's, because a root is the one window every
        client legitimately names that no client owns: it is the parent of
        each top-level window and the drawable a graphics context is made
        against.  Rules that gate a foreign window have to let it through.
        Walking the remaining screens means stepping over each screen's depth
        and visual lists, so it is done after self.root is already set: if
        that walk ever fails, the first screen's root is still known.
        """
        vendor = struct.unpack_from(self.endian + "H", setup_body, 16)[0]
        screens, formats = setup_body[20], setup_body[21]
        offset = 32 + vendor + (4 - vendor % 4) % 4 + 8 * formats
        if len(setup_body) >= offset + 4:
            self.root = self.word(setup_body, offset)
            self.roots = {self.root}
        try:
            for _ in range(screens):
                if len(setup_body) < offset + 40:
                    break
                root = self.word(setup_body, offset)
                self.roots.add(root)
                # SCREEN width/height-in-pixels sit at offset +20 and +22, and
                # are what "fullscreen" is measured against -- *per screen*.
                # Keeping only the first screen's meant every window was judged
                # against that one, so a borderless window covering a second,
                # smaller screen was not fullscreen by any measure the policy
                # took: measured on a two-screen server, 640x480 over the whole
                # of screen 1 came back with its override-redirect intact while
                # the same trick on screen 0 was stripped.  A laptop with a
                # projector is the ordinary case here, not an exotic one.
                width = struct.unpack_from(
                    self.endian + "H", setup_body, offset + 20)[0]
                height = struct.unpack_from(
                    self.endian + "H", setup_body, offset + 22)[0]
                self.screen_size[root] = (width, height)
                if root == self.root:
                    self.root_depth = setup_body[offset + 38]
                    self.root_visual = self.word(setup_body, offset + 32)
                    self.screen_width, self.screen_height = width, height
                depths = setup_body[offset + 39]
                offset += 40
                for _ in range(depths):
                    visuals = struct.unpack_from(
                        self.endian + "H", setup_body, offset + 2)[0]
                    offset += 8 + 24 * visuals
        except (struct.error, IndexError):
            pass

    def is_foreign_window(self, window):
        """is_foreign(), except that a root window is nobody's and everybody's.

        Every client names a root: as the parent of its top-level windows, as
        the drawable it makes a graphics context against.  A root is created
        by the server, so the plain range test calls it foreign, which is the
        right answer for *writing* to it and the wrong one for the requests
        that merely have to name it.
        """
        return window not in self.roots and self.is_foreign(window)

    # -- fullscreen-overlay detection (spoofing defence) -------------------

    def _is_fullscreen(self, width, height, root=None):
        """True if a window this size covers most of **its own** screen -- the
        size a desktop-spoof overlay wants.  Unknown screen size answers False.

        The screen matters: judging every window against the first one left a
        second, smaller screen with no spoof defence at all.
        """
        sw, sh = self.screen_size.get(root, (self.screen_width,
                                             self.screen_height))
        return (bool(sw) and bool(sh)
                and width >= sw * FULLSCREEN_FRACTION
                and height >= sh * FULLSCREEN_FRACTION)

    def _screen_of(self, parent):
        """The root of the screen a window created under `parent` is on."""
        if parent in self.roots:
            return parent
        state = self.profile.window_state(parent)
        return state[5] if state else self.root

    def _value_offset(self, base, mask, bit):
        """Byte offset of `bit`'s value in a value-list at `base`: values appear
        in ascending bit order, 4 bytes each, only for the bits that are set."""
        return base + 4 * bin(mask & (bit - 1)).count("1")

    def _stripped_override(self, body, base, mask):
        """`body` with the override-redirect value zeroed -- the neutralised
        form of a request that would have made a fullscreen overlay bypass the
        window manager.  The window is then managed (framed) like any other."""
        patched = bytearray(body)
        offset = self._value_offset(base, mask, CW_OVERRIDE_REDIRECT)
        if len(patched) >= offset + 4:
            struct.pack_into(self.endian + "I", patched, offset, 0)
        return bytes(patched)

    def _tracked_size(self, window):
        """The size the policy believes a tracked own window has, or (0, 0)."""
        state = self.profile.window_state(window)
        return (state[0], state[1]) if state else (0, 0)

    def _pointer_bound(self, window):
        """The size to bound a QueryPointer reply against, or None to blank it.

        A position is kept only over a window the application owns, that it has
        mapped, and whose size the policy knows: that is the irreducible case
        the ninth pass named -- the client could work the position out from its
        own window's origin anyway.  Everything else answers None, and None now
        means *blank*, where it used to mean "leave the position alone".  That
        default was the hole: the root window is not tracked, so the plainest
        form of the question -- QueryPointer on the root, which is how every
        toolkit asks where the mouse is -- returned the true global position
        through the proxy, and so did a query about a window the client had
        created huge and never mapped.  Both were measured.
        """
        state = self.profile.window_state(window)
        if state is None or not state[3]:            # unknown, or not mapped
            return None
        return (state[0], state[1])

    def _covered_in_pieces(self):
        """The gate verdict when the client's override-redirect windows cover
        the screen *between them*, or None.

        The threshold is the area a single window of FULLSCREEN_FRACTION in
        each dimension would have, so the rule that catches one window and the
        rule that catches four agree about how much of the screen is too much.
        The model records what the client asked for rather than what it got --
        the convention the override-redirect tracking already follows -- so a
        refused map leaves its window counted, and the next one is gated too.
        That is the fail-closed direction, and the operation log names it.
        """
        for root, covered in self.profile.override_area_by_screen().items():
            width, height = self.screen_size.get(
                root, (self.screen_width, self.screen_height))
            if not (width and height):
                continue
            if covered >= width * height * FULLSCREEN_FRACTION ** 2:
                return (("fullscreen", None),
                        "override-redirect windows covering a screen "
                        "between them")
        return None

    def judge_fullscreen(self, opcode, body):
        """Track own windows' size and override-redirect state, and gate the
        request that would tip one into a fullscreen override-redirect overlay
        -- whether it is created that way, resized into it, or made
        override-redirect after the fact.  Returns (verdict, reason) for such a
        request, or None.  The verdict is ("fullscreen", deny_body): forward()
        forwards `body` if the user allows the takeover, else `deny_body`
        (override-redirect stripped), or a NoOp if deny_body is None."""
        if opcode == 1 and len(body) >= 28:            # CreateWindow
            window = self.word(body, 0)
            if self.is_foreign(window):
                return None
            width = struct.unpack_from(self.endian + "H", body, 12)[0]
            height = struct.unpack_from(self.endian + "H", body, 14)[0]
            mask = self.word(body, 24)
            override = False
            if mask & CW_OVERRIDE_REDIRECT:
                offset = self._value_offset(28, mask, CW_OVERRIDE_REDIRECT)
                if len(body) < offset + 4:
                    return "silent", "unreadable window attributes"
                override = bool(self.word(body, offset))
            root = self._screen_of(self.word(body, 4))
            self.profile.note_window(window, self.word(body, 4),
                                     width, height, override, root)
            if override and self._is_fullscreen(width, height, root):
                return (("fullscreen",
                         self._stripped_override(body, 28, mask)),
                        "override-redirect fullscreen window")
        elif opcode == 2 and len(body) >= 8:           # ChangeWindowAttributes
            window = self.word(body, 0)
            if self.is_foreign(window):
                return None
            mask = self.word(body, 4)
            if mask & CW_OVERRIDE_REDIRECT:
                offset = self._value_offset(8, mask, CW_OVERRIDE_REDIRECT)
                if len(body) < offset + 4:
                    # The value list stops before the word this gate reads, so
                    # the gate cannot run.  Refuse rather than skip: it is the
                    # fail-open the seventeenth pass swept out of the
                    # resource-id gates, here in the value-list mechanism -- and
                    # this is the gate that keeps a borderless window off the
                    # whole screen.  Such a request is malformed anyway, since X
                    # wants exactly one word per mask bit, but that is the
                    # server's reasoning and not one the policy may lean on.
                    return "silent", "unreadable window attributes"
                if self.word(body, offset):
                    self.profile.note_override(window, True)
                    width, height = self._tracked_size(window)
                    state = self.profile.window_state(window)
                    if self._is_fullscreen(width, height,
                                           state[5] if state else None):
                        return (("fullscreen",
                                 self._stripped_override(body, 8, mask)),
                                "override-redirect fullscreen window")
                    if self._covered_in_pieces():
                        return (("fullscreen",
                                 self._stripped_override(body, 8, mask)),
                                "override-redirect windows covering the "
                                "screen between them")
                else:
                    self.profile.note_override(window, False)
        elif opcode == 12 and len(body) >= 8:          # ConfigureWindow
            window = self.word(body, 0)
            if self.is_foreign(window):
                return None
            mask = struct.unpack_from(self.endian + "H", body, 4)[0]
            state = self.profile.window_state(window)
            width, height = (state[0], state[1]) if state else (0, 0)
            for bit in (CONFIGURE_WIDTH, CONFIGURE_HEIGHT):
                if not mask & bit:
                    continue
                off = self._value_offset(8, mask, bit)
                if len(body) < off + 4:      # unreadable: refuse, do not skip
                    return "silent", "unreadable window configuration"
                if bit == CONFIGURE_WIDTH:
                    width = self.word(body, off) & 0xFFFF
                else:
                    height = self.word(body, off) & 0xFFFF
            self.profile.note_geometry(window, width, height)
            # An untracked window is treated as override-redirect here rather
            # than as an ordinary one: the model can only lose a window by the
            # server having freed it or by the id being one we never saw
            # created, and neither is a reason to hand back the gate.
            override = state[2] if state else True
            root = state[5] if state else None
            if override and not self._is_fullscreen(width, height, root):
                covered = self._covered_in_pieces()
                if covered is not None:
                    return covered
            if override and self._is_fullscreen(width, height, root):
                # Override-redirect cannot be cleared by ConfigureWindow, so the
                # resize itself is dropped: the overlay never reaches fullscreen.
                return (("fullscreen", None),
                        "override-redirect window resized to fullscreen")
        return None

    def _names_fullscreen_state(self, body):
        """True if a _NET_WM_STATE ClientMessage (in a SendEvent body) adds or
        toggles _NET_WM_STATE_FULLSCREEN -- the EWMH route to fullscreen."""
        if len(body) < 32:
            return False
        if self.atom_name(self.word(body, 16)) != NET_WM_STATE:
            return False
        action = self.word(body, 20)
        if action not in NET_WM_STATE_ADDING:
            return False
        return NET_WM_STATE_FULLSCREEN in (
            self.atom_name(self.word(body, 24)),
            self.atom_name(self.word(body, 28)))

    def _property_adds_fullscreen(self, body):
        """The _NET_WM_STATE property value in a ChangeProperty body, if it
        lists _NET_WM_STATE_FULLSCREEN -- the offset of that atom, or None."""
        if len(body) < 20 or self.atom_name(self.word(body, 4)) != NET_WM_STATE:
            return None
        if body[12] != 32:                             # format must be 32-bit
            return None
        count = self.word(body, 16)
        for i in range(count):
            offset = 20 + 4 * i
            if len(body) < offset + 4:
                break
            if self.atom_name(self.word(body, offset)) == NET_WM_STATE_FULLSCREEN:
                return offset
        return None

    def _takeover_allowed(self, action, what):
        """Whether an untrusted client may take something the whole session
        shares, by the same --gate the clipboard uses: allow always, ask puts
        it to the user (blocking this connection thread on the prompt, as a
        paste does), deny (the default) refuses.  Reached only when enforcing.

        Two things go through it.  The screen, which a borderless window can
        cover; and the **keyboard**, which any client may grab on a window of
        its own -- and while an active grab is held the server delivers every
        keystroke to the grabbing client, wherever the user is typing.  That
        is the keylogger this whole project exists to prevent, reached without
        naming a foreign window, an extension, or the root: measured through
        the proxy, a client grabbed the keyboard on a window of its own and
        read back the keycodes for a word typed somewhere else entirely.
        """
        if self.gate_mode == "allow":
            return True
        if self.gate_mode == "ask" and self.gate is not None:
            return self.gate.decide(self.conn_token, self.describe(), what,
                                    action, self.peer_label(), action=action)
        return False

    def _fullscreen_allowed(self):
        return self._takeover_allowed("fullscreen", "the whole screen")

    def inspect(self, opcode, minor, body):
        """Learn extension opcodes and atom names, and nothing else.

        The enforcing proxy keeps no per-request statistics -- the operations
        log records each new operation once, which is all the allowlist needs
        -- so it skips the counting the profiler's inspect() does and runs
        only the naming bookkeeping.
        """
        self.learn(opcode, minor, body)

    # -- policy ------------------------------------------------------------

    def judge(self, opcode, minor, body):
        """Return (verdict, reason).

        verdict is "allow", "gate", "silent" (drop, no answer expected),
        or a callable taking the sequence number and returning the reply
        bytes to send instead.
        """
        if opcode >= 128:
            if opcode in self.denied_opcodes:
                # Answered rather than dropped.  A client is told these
                # extensions are absent, so anything addressed to one is either
                # a guess at its (stable, guessable) opcode or a bug -- and
                # dropping it silently left a reply-bearing request waiting for
                # a reply that never came: measured under Xephyr, which unlike
                # Xvfb actually has Composite, an attacker that guessed the
                # opcode and asked its QueryVersion simply hung.  BadRequest is
                # also the *truthful* answer: it is exactly what a server with
                # no such extension would send, so the opcode agrees with what
                # QueryExtension said instead of behaving like nothing at all.
                return ((lambda seq: self.error(seq, BAD_REQUEST, opcode, minor)),
                        "extension denied")
            name = self.extension_opcodes.get(opcode) \
                or self.profile.extension_name(opcode)
            # One dispatch, one allowlist: an extension is admitted iff it has
            # an inspector here, and it is routed through the same table, so
            # there is no path that allows an extension request without
            # inspecting it.  Anything else -- an extension nobody profiled, a
            # new one nobody has looked at -- is blocked by default-deny.
            inspector = EXTENSION_INSPECTORS.get(name)
            if inspector is not None:
                return getattr(self, inspector)(opcode, minor, body)
            return "block", "extension not on the allowlist"

        if opcode == 98:                                   # QueryExtension
            length = struct.unpack_from(self.endian + "H", body, 0)[0]
            name = body[4:4 + length].decode("latin-1")
            if name in KNOWN_DENIED_EXTENSIONS:
                return "hide-extension", "extension denied"
            if name not in ALLOWED_EXTENSIONS:
                # Not denied outright, but not allowlisted either -- so every
                # request in it would be blocked.  Saying "present" and then
                # refusing hangs the client: the blocked-request path answers
                # NoOperation, and a reply-bearing extension request waits for
                # a reply that never comes.  Reporting the extension absent
                # instead puts the client on the code path it already has for
                # a server that lacks it, which is the one every toolkit
                # tests.  (X-Resource and MIT-SCREEN-SAVER are the usual ones.)
                return "hide-extension", "extension not on the allowlist"
            return "allow", None

        if opcode == 24:                                   # ConvertSelection
            # The *requestor* (offset 0) is the window the selection's owner
            # will write its answer into, and it was never checked -- so a
            # client could name somebody else's window and have a trusted
            # application deposit data there, under a property name of the
            # client's choosing.  Measured under the default --gate deny: a
            # write the policy refuses outright ("writes foreign property")
            # went through when it was asked for this way instead, the owner
            # doing it on the client's behalf.  Worse, when the client owns
            # the selection itself, the *server* then sends it a genuine
            # SelectionRequest naming that window -- which is exactly what
            # EV-7 trusts to grant foreign property writes, so the client
            # could mint its own grant.  EV-7 refused a SendEvent forgery;
            # this route needed no forgery at all, only a field nobody read.
            #
            # A client converts a selection into its *own* window: that is
            # what ICCCM describes and what every toolkit does.  Refused
            # rather than rewritten, because the answer travels to the
            # requestor, so there is nothing to hand back to this client.
            if len(body) >= 4 and self.is_foreign(self.word(body, 0)):
                return "silent", "selection converted into a foreign window"
            if self.is_gated_selection(self.word(body, 4)):
                if self.gate_mode == "allow":
                    return "allow", None
                if self.gate_mode == "ask" and self.gate is not None:
                    return "ask", "selection put to the user"
                return "gate", GATE_REFUSED
            return "allow", None

        if opcode in SCREEN_REFERENCE_REQUESTS:
            if self.names_foreign_window(SCREEN_REFERENCE_REQUESTS, opcode, body):
                return "silent", "screen reference to a foreign window"
            return "allow", None

        if opcode in SCREEN_REFERENCE_REPLIES:
            if self.names_foreign_window(SCREEN_REFERENCE_REPLIES, opcode, body):
                if opcode == 97:                  # QueryBestSize
                    # echo the size that was asked for: a plausible answer
                    size = body[4:8] if len(body) >= 8 else b"\0" * 4
                    return ((lambda seq: self.reply(seq, size)),
                            "screen reference to a foreign window")
                return ((lambda seq: self.reply(seq, b"\0" * 2)),
                        "colormaps installed on a foreign window's screen")
            return "allow", None

        if opcode in CURSOR_SOURCE_REQUESTS:
            if self.names_foreign(CURSOR_SOURCE_REQUESTS, opcode, body):
                return "silent", "cursor built from a foreign resource"
            return "allow", None

        if opcode == 14:                                   # GetGeometry
            if self.is_foreign_window(self.word(body, 0)):
                return ((lambda seq: self._blank_geometry(seq)),
                        "foreign window geometry")
            return "allow", None

        if opcode == 3:                                    # GetWindowAttributes
            if self.is_foreign_window(self.word(body, 0)):
                return ((lambda seq: self._blank_attributes(seq)),
                        "foreign window attributes")
            return "allow", None

        if opcode == 40 and len(body) >= 8:                # TranslateCoordinates
            # Menus translate their own window against a root, and a drag
            # source looks for the drop target with root-to-root -- so gating
            # the *arguments* costs neither.  The foreign window id a drag is
            # actually after comes back in the reply's child field (offset 8),
            # which is the QueryTree enumeration residual and follows the same
            # same DENY_QUERYTREE rule.
            if self.is_foreign_window(self.word(body, 0)) or \
                    self.is_foreign_window(self.word(body, 4)):
                return ((lambda seq: self.reply(seq, first=1)),
                        "coordinates of a foreign window")
            if DENY_QUERYTREE:
                return ("scrub", [(8, 4)]), "window under the pointer"
            return "allow", None

        if opcode == 1 and len(body) >= 8:                  # CreateWindow
            # The parent is at offset 4.  A window created inside another
            # client's window is clipped to it, drawn over its contents and
            # collects input across that area -- the same overlay
            # ReparentWindow is refused for, reached without reparenting
            # anything.  A root parent is the ordinary case and is allowed.
            if self.is_foreign_window(self.word(body, 4)):
                return "silent", "window created inside a foreign window"
            fullscreen = self.judge_fullscreen(1, body)
            if fullscreen is not None:
                return fullscreen
            return "allow", None

        if opcode in FOREIGN_RESOURCE_REQUESTS:
            if self.names_foreign(FOREIGN_RESOURCE_REQUESTS, opcode, body):
                return "silent", "names another client's resource"
            return "allow", None

        if opcode == 51:                                   # SetFontPath
            # The font path is server-global.  A forwarded application that
            # empties or redirects it breaks font loading for every other
            # client in the session -- the same shape as the screensaver and
            # keyboard-mapping rules, and no business of a remote client.
            return "silent", "server-global font path"

        if opcode in WINDOW_WRITE_REQUESTS:
            # ReparentWindow names two windows: the one being moved (offset 0)
            # and its new parent (offset 4).  Only the first is gated --
            # putting your *own* window under a foreign parent is how XEmbed
            # and system-tray icons work, while putting a *foreign* window
            # under yours is how you capture another application's input.
            if self.is_foreign(self.word(body, 0)):
                return "silent", "modifies a foreign window"
            if opcode == 12 and self.configures_foreign_sibling(body):
                return "silent", "restacks against a foreign window"
            if opcode == 12:
                fullscreen = self.judge_fullscreen(12, body)
                if fullscreen is not None:
                    return fullscreen
            # The request is allowed, so the model follows the window through
            # it: mapped and unmapped decide whether the pointer may be
            # reported over it, and a destroyed window (with everything under
            # it) leaves the model entirely -- both because the server has
            # freed the id and may hand it back for a different window, and
            # because a model that only ever grows is a leak a client can
            # drive by creating and destroying windows in a loop.
            window = self.word(body, 0)
            if opcode in (8, 9):                           # Map[Sub]Windows
                self.profile.note_mapped(window, True, subwindows=opcode == 9)
                # Mapping is where a covering becomes a fake desktop: the
                # windows exist unmapped without covering anything.
                covered = self._covered_in_pieces()
                if covered is not None:
                    return covered
            elif opcode in (10, 11):                       # Unmap[Sub]Windows
                self.profile.note_mapped(window, False, subwindows=opcode == 11)
            elif opcode in (4, 5):                         # Destroy[Sub]Windows
                self.profile.forget_window(window, subwindows=opcode == 5)
            elif opcode == 7 and len(body) >= 8:           # ReparentWindow
                self.profile.reparent_window(window, self.word(body, 4))
            return "allow", None

        if opcode == 22:                                   # SetSelectionOwner
            # The clipboard gate guards ConvertSelection -- the filtered
            # client *reading* a selection.  Taking ownership is the other
            # half of the same capability: it puts the user's real copy out of
            # reach, and every later paste anywhere on the desktop asks this
            # client what to paste.  So it goes through the same gate the read
            # does rather than being refused outright, because offering a copy
            # outward is something the policy means to permit once the user
            # has said so.  Releasing ownership (owner None) is left alone: a
            # client can only release what it already holds.
            if self.word(body, 0) and self.is_gated_selection(self.word(body, 4)):
                if self.gate_mode == "allow":
                    return "allow", None
                if self.gate_mode == "ask" and self.gate is not None:
                    return "ask-owner", "selection ownership put to the user"
                return "silent", GATE_OWNER_REFUSED
            return "allow", None

        if opcode == 20:                                   # GetProperty
            window, atom = self.word(body, 0), self.word(body, 4)
            if self.is_foreign(window) and \
                    self.atom_name(atom) not in FOREIGN_PROPERTY_ALLOW:
                return (lambda seq: self.reply(seq)), "foreign property"
            return "allow", None

        if opcode == 21:                                   # ListProperties
            if self.is_foreign(self.word(body, 0)):
                return (lambda seq: self.reply(seq)), "foreign property"
            return "allow", None

        if opcode == 43:                                   # GetInputFocus
            # OF-1.  The reply names whichever window holds the focus, so
            # polling it is a complete trace of which window the user is
            # working in -- the pull half of the focus tracking that refusing
            # FocusChange on foreign windows closed the push half of.  The
            # focus window sits at offset 8 of the 32-byte reply and is
            # blanked only when it is somebody else's, so "do I have focus?"
            # still answers correctly.  Measured under openbox and metacity:
            # both focus the client's own window, not a frame.
            return ("scrub-foreign", ([8], 0)), "foreign focus window"

        if opcode == 15:                                   # QueryTree
            if DENY_QUERYTREE and self.is_foreign(self.word(body, 0)):
                tree = struct.pack(self.endian + "IIH", self.root, 0, 0)
                return (lambda seq: self.reply(seq, tree)), "foreign window"
            return "allow", None

        if opcode == 73:                                   # GetImage
            if self.is_foreign(self.word(body, 0)):
                return ((lambda seq: self.error(seq, BAD_ACCESS, 73, 0)),
                        "screen capture")
            return "allow", None

        if opcode in (62, 63):                             # CopyArea/CopyPlane
            # Source at 0, destination at 4.  Reading a foreign drawable is
            # capture; writing one paints into somebody else's window, and
            # only the read was ever checked.
            if self.is_foreign(self.word(body, 0)):
                return "silent", "reads foreign drawable"
            if len(body) >= 8 and self.is_foreign(self.word(body, 4)):
                return "silent", "draws into a foreign drawable"
            return "allow", None

        if opcode in (26, 31):                             # Grab{Pointer,Keyboard}
            if self.is_foreign(self.word(body, 0)):
                # status = AlreadyGrabbed, an outcome every client handles
                return ((lambda seq: self.reply(seq, first=1)),
                        "grab on foreign window")
            # A keyboard grab on the client's own window steals every
            # keystroke in the session while it is held -- measured, a word
            # typed elsewhere came back as keycodes.  Refusing it was tried
            # and measured too, and costs more than it is worth: GTK asks for
            # the pointer and the keyboard in one request, so a refusal makes
            # menus not open at all, which is what a person would call broken.
            #
            # So the grab is allowed and the *delivery* is bounded instead,
            # exactly as the pointer grab's positions are: a key event reaches
            # this client only while a window of its own holds the focus (see
            # patch_event).  A menu is opened by an application the user is
            # working in, so it keeps its keys; a client watching from the
            # background is not, so it gets nothing.
            self.keyboard_grabbed = True
            return "allow", None

        if opcode == 32:                                   # UngrabKeyboard
            self.keyboard_grabbed = False
            return "allow", None

        if opcode in (28, 33, 29, 34):    # Grab/Ungrab {Button,Key}
            # All four name the grab window at the same offset, and the
            # release is gated exactly like the grab: a client undoes what it
            # was allowed to take, and an ungrab against somebody else's
            # window is as meaningless as the grab would have been.
            if self.is_foreign(self.word(body, 0)):
                return "silent", "grab on foreign window"
            return "allow", None

        if opcode == 2:                                    # ChangeWindowAttributes
            window, mask = self.word(body, 0), self.word(body, 4)
            if self.is_foreign(window):
                # Everything outside CW_PER_CLIENT is an attribute of the
                # window itself, so setting it changes what the window's real
                # owner displays: its background, its border, its colormap,
                # the cursor shown over it, whether the window manager sees it
                # at all.
                if mask & ~CW_PER_CLIENT:
                    return "silent", "changes a foreign window's attributes"
                if mask & CW_EVENT_MASK:
                    # The event mask a client selects on a window it does not
                    # own is now an allowlist, not a block-list: it may name
                    # only FOREIGN_EVENT_MASK_ALLOW, and anything else -- an
                    # input tap, StructureNotify, ResizeRedirect, a future bit
                    # nobody has catalogued -- is refused and logged.  Default
                    # is deny; PropertyChange is the one allowed bit, and its
                    # events are still filtered by the EV-3 handler.  A body too
                    # short to carry the mask is refused too, rather than passed
                    # for want of a value to check (fail closed, not open).
                    offset = self._value_offset(8, mask, CW_EVENT_MASK)
                    if len(body) < offset + 4:
                        return "silent", "unreadable event mask on a foreign window"
                    wanted = self.word(body, offset)
                    if wanted & ~FOREIGN_EVENT_MASK_ALLOW:
                        return ("silent",
                                "selects a disallowed event on a foreign window")
            else:
                # Own window: making it override-redirect while it is (or is
                # sized to be) fullscreen is the second assembly path for a
                # desktop-spoof overlay.
                fullscreen = self.judge_fullscreen(2, body)
                if fullscreen is not None:
                    return fullscreen
            return "allow", None

        if opcode == 25:                                   # SendEvent
            destination = self.word(body, 0)
            code = body[8] & 0x7F if len(body) >= 20 else 0
            # SE-1.  PointerWindow (0) and InputFocus (1) are not the client's
            # own windows: the server delivers to whatever window is under the
            # pointer or holds the keyboard focus, which as a rule is a trusted
            # one.  A synthetic Key/Button/Motion event sent there is forged
            # input into someone else's window -- the write-direction twin of
            # the input taps refused above, and reached past the foreign-window
            # check because the destination is a special value, not an XID.
            # (Well-behaved clients ignore SendEvent-flagged input, but the
            # proxy must not rest on the target's hygiene.)  Injecting to the
            # client's *own* window is harmless and still passes below.
            if destination in (0, 1) and code in SYNTHETIC_INPUT_CODES:
                return "silent", "synthetic input to the focused/pointed window"
            if destination in (0, 1) or not self.is_foreign(destination):
                return "allow", None
            if len(body) >= 20:
                if code == 33:                              # ClientMessage
                    message = self.atom_name(self.word(body, 16))
                    if message in EWMH_MESSAGES:
                        # The event's own window field, at offset 12, is the
                        # window the message acts on.  Checking only the
                        # message type let _NET_CLOSE_WINDOW name somebody
                        # else's window and reach the window manager intact --
                        # the window-tree attack of WINDOW_WRITE_REQUESTS,
                        # routed through a request the policy was allowing.
                        if message in EWMH_WINDOW_TARGETS and \
                                self.is_foreign(self.word(body, 12)):
                            return "silent", "EWMH message names a foreign window"
                        # The EWMH route to a borderless fullscreen window: ask
                        # the window manager to add _NET_WM_STATE_FULLSCREEN.
                        # Gated like the override-redirect route; dropped when
                        # refused, so the window manager never fullscreens it.
                        if self._names_fullscreen_state(body):
                            return ("fullscreen", None), "EWMH fullscreen request"
                        return "allow", None
                elif code == 31:                            # SelectionNotify
                    # Answering a selection request: the reply always goes
                    # to another client's window, and refusing it leaves
                    # whoever asked us waiting for a timeout.  This is the
                    # outbound direction -- pasting *out* of the filtered
                    # application -- which the policy is meant to permit.
                    if self.granted(self.selection_requestors, destination):
                        return "allow", None
            return "silent", "event to foreign window"

        if opcode == 18:                                   # ChangeProperty
            window, atom = self.word(body, 0), self.word(body, 4)
            if self.is_foreign(window) and \
                    not self.granted(self.selection_requests, (window, atom)):
                return "silent", "writes foreign property"
            # Setting _NET_WM_STATE = [..._NET_WM_STATE_FULLSCREEN...] directly
            # (rather than by ClientMessage) is the same EWMH fullscreen route
            # at map time.  When refused, the fullscreen atom is zeroed out of
            # the value and the rest of the state list is left intact.
            if not self.is_foreign(window):
                offset = self._property_adds_fullscreen(body)
                if offset is not None:
                    patched = bytearray(body)
                    struct.pack_into(self.endian + "I", patched, offset, 0)
                    return (("fullscreen", bytes(patched)),
                            "EWMH fullscreen property")
            return "allow", None

        if opcode in (19, 114):                            # Delete/RotateProperties
            if self.is_foreign(self.word(body, 0)):
                return "silent", "writes foreign property"
            return "allow", None

        if opcode in (109, 111, 113):        # ChangeHosts/AccessControl/Kill
            return "silent", "server administration"

        if opcode in (36, 37):               # GrabServer / UngrabServer
            # A server grab stops every other client being served, input
            # included, so the user cannot even reach a terminal to kill the
            # offender.  Toolkits use it rarely and cope without it.  Both
            # expect no reply, so NoOperation is answer enough.
            return "silent", "server grab"

        if opcode == 100:                    # ChangeKeyboardMapping
            return "silent", "remaps the shared keyboard"

        if opcode in (116, 118):             # Set{Pointer,Modifier}Mapping
            # These reply with a status.  Answer Success but forward nothing,
            # so the client is not broken by an error yet the shared mapping
            # is left alone.
            return ((lambda seq: self.reply(seq)),
                    "remaps shared input")

        if opcode == 42:                     # SetInputFocus
            focus = self.word(body, 0)
            if focus not in (0, 1) and self.is_foreign(focus):
                # None and PointerRoot are legitimate resets; taking focus
                # into a foreign window routes the user's typing there.
                return "silent", "input focus to a foreign window"
            return "allow", None

        if opcode == 41:                     # WarpPointer
            if len(body) >= 8:
                dst = self.word(body, 4)
                if dst and self.is_foreign(dst):
                    return "silent", "pointer warp into a foreign window"
            return "allow", None

        if opcode == 23:                     # GetSelectionOwner
            # The core poll of the fact XFIXES SelectSelectionInput is refused
            # for watching.  On a gated selection the owner is replaced with a
            # stand-in when it is somebody else's, and answered truthfully when
            # it is the client's own (see SELECTION_OWNER_STANDIN).  Selections
            # outside the gated three -- WM_S0, _NET_WM_CM_S0, the system tray
            # manager -- are how a client finds the window manager or the
            # compositor and are left alone.
            if self.is_gated_selection(self.word(body, 0)):
                return (("scrub-foreign", ([8], SELECTION_OWNER_STANDIN)),
                        "who owns a gated selection")
            return "allow", None

        if opcode == 103:                    # GetKeyboardControl
            # The reply's LED mask (offset 8) is the live lock state of the
            # keyboard every client shares: Caps, Num and Scroll Lock, and
            # whatever else the layout binds an indicator to.  Polling it is
            # the modifier-state monitor XkbGetState is already blanked for,
            # under another name -- each transition is a key the user pressed.
            # The rest of the reply is configuration (auto-repeat, bell, the
            # per-key repeat map) and is answered truthfully.
            return ("scrub", [(8, 4)]), "keyboard lock-state poll"

        if opcode == 44:                     # QueryKeymap
            # Returns a bitmap of every key currently down, for the whole
            # server, to any client that asks -- poll it in a loop and it is a
            # keylogger with no extension and no grab, the core-protocol twin
            # of the XInput tap.  Answer a keymap with nothing pressed.
            return ((lambda seq: self._empty_keymap(seq)),
                    "keyboard state poll")

        if opcode == 38:                     # QueryPointer
            # The reply's button/modifier mask is always blanked (the input-
            # state monitor).  Beyond that, the reply carries the *global*
            # pointer position even when the pointer is over another window, so
            # a client polling over a window it owns reads the pointer anywhere
            # on the screen.  bound_pointer_reply keeps the position only when
            # the reply proves the pointer is over this window (using its
            # tracked size) and blanks it otherwise, leaving menus and drag --
            # which query while the pointer really is over their own window --
            # working.  An untracked window's size is unknown, so its position
            # is left intact rather than over-blocked.
            size = self._pointer_bound(self.word(body, 0))
            return ("pointer", (size, "core")), "pointer position and input-state"

        if opcode in (107, 115):             # SetScreenSaver / ForceScreenSaver
            # A remote application should not be able to change the screensaver
            # timeout or force it off and keep your session from auto-locking.
            return "silent", "screensaver control"

        # Default deny: a core request that reached here is neither on the
        # safe allowlist nor covered by a rule above, so it is blocked and
        # logged rather than passed on trust.
        if opcode in SAFE_CORE:
            return "allow", None
        return "block", "not on the allowlist"

    # -- extension argument inspection -------------------------------------

    #: XI2 event bits for a key going down or coming up.  A grab that asks for
    #: these is asking for the keyboard, whatever device id it names.
    XI_KEY_EVENTS = (1 << 2) | (1 << 3)

    def _xi_mask_wants_keys(self, body):
        """True if an XIGrabDevice body asks for key events.

        The request ends with a mask, its length in words at offset 18 and the
        words themselves at 20.  A body too short to carry the mask answers
        True: a grab whose terms cannot be read is not one to allow.
        """
        if len(body) < 20:
            return True
        words = struct.unpack_from(self.endian + "H", body, 18)[0]
        if not words:
            return True                  # a grab that names no events at all
        for index in range(words):
            offset = 20 + 4 * index
            if len(body) < offset + 4:
                return True
            if index == 0 and self.word(body, offset) & self.XI_KEY_EVENTS:
                return True
        return False

    def _mask_is_input_tap(self, body):
        """True if an XISelectEvents body asks for any event that leaks input.

        That is the key/button/motion/touch taps *and* the crossing and focus
        events, which carry the global pointer position and the modifier state
        (XI_FOREIGN_EVENT_MASK) -- the tenth pass widened this from the taps
        alone.  Each mask word is read in the connection's byte order.
        """
        num_masks = struct.unpack_from(self.endian + "H", body, 4)[0]
        byteorder = "little" if self.endian == "<" else "big"
        offset = 8
        for _ in range(num_masks):
            if len(body) < offset + 4:
                break
            mask_len = struct.unpack_from(self.endian + "H", body, offset + 2)[0]
            mask = int.from_bytes(
                body[offset + 4:offset + 4 + mask_len * 4], byteorder)
            if mask & XI_FOREIGN_EVENT_MASK:
                return True
            offset += 4 + mask_len * 4
        return False

    def names_foreign_window(self, table, opcode, body):
        """As names_foreign, but a root window is nobody's -- see
        is_foreign_window."""
        return self._names(table, opcode, body, self.is_foreign_window)

    def names_foreign(self, table, minor, body):
        """True if any resource this extension request names is another
        client's.  The table maps a minor opcode to the body offsets that
        carry a resource id, skipping the server-allocated ones."""
        return self._names(table, minor, body, self.is_foreign)

    def _names(self, table, key, body, foreign):
        """True if a gated field is foreign **or unreadable**.

        The second half is the point.  These loops used to skip an offset the
        body was too short to hold -- `len(body) >= offset + 4 and ...` -- and
        fall out of the bottom as "names nothing foreign", which is a
        fail-open: a request the policy could not read was forwarded on the
        strength of having read nothing.  The same shape was found by hand
        twice before (XKB's GetDeviceInfo, the foreign-window event mask) and
        fixed where it was found; a sweep of every gated request against every
        truncation of its body found the rest, all in these two helpers and
        their core equivalents.  Nothing was exploitable through them -- a
        request too short for a field at offset 0 is one the server rejects as
        BadLength -- but "the server would have caught it" is not a rule the
        policy gets to rely on, and it is the exact fail-open this file spends
        itself refusing elsewhere.
        """
        for offset in table.get(key, ()):
            if len(body) < offset + 4 or foreign(self.word(body, offset)):
                return True
        return False

    def refuse_extension(self, major, minor, replies, reason):
        """Refuse an extension request, answering only if one is expected.

        A blocked request that expects a reply must be given one or the client
        waits for it forever.  The generic blocking path in forward() decides
        that with REPLY_REQUESTS, which lists core opcodes only -- every
        extension request has a major opcode of 128 or more, so it looks
        reply-less there.  Each inspector therefore names the reply-bearing
        minors it refuses, and those get an error, which consumes the sequence
        number and unblocks the client; the rest are dropped silently.
        """
        if minor in replies:
            return ((lambda seq: self.error(seq, BAD_ACCESS, major, minor)),
                    reason)
        return "silent", reason

    def _blank_cursor(self, sequence, named=False):
        """A cursor image reply describing a 1x1 fully transparent cursor.

        Refusing outright would mean an error, and Xlib's default handler
        exits the process on one; a well-formed answer that says nothing is
        the trick QueryKeymap's empty keymap already plays.  Both replies
        carry one 32-bit pixel past their 32-byte base, so the length is 1.
        """
        head = struct.pack(self.endian + "BxHI", 1, sequence, 1)
        fixed = struct.pack(self.endian + "hhHHHHI", 0, 0, 1, 1, 0, 0, 0)
        if named:
            # cursor atom None, and a zero-length name
            tail = struct.pack(self.endian + "IHxx", 0, 0)
        else:
            tail = b"\0" * 8
        return head + fixed + tail + b"\0" * 4

    def judge_xkb(self, major, minor, body):
        """XKEYBOARD may be read, not written.

        judge() blocks ChangeKeyboardMapping, SetModifierMapping and
        SetPointerMapping because they remap input every other client shares.
        XkbSetMap, XkbSetControls, XkbSetNames and XkbLatchLockState do the
        same thing through the extension, so the core door was locked and the
        extension window beside it left open -- the shape of hole XF-02 found
        for reading input, in the write direction.  The allowlist is of
        queries and per-connection state; everything else is refused.

        What it may not read is the keyboard's live *state*, in either of the
        two forms the extension offers it.  The modifier and group state
        (XkbGetState) was blanked in the ninth pass; the lock state -- the
        indicators, which is where Caps, Num and Scroll Lock show up -- is
        blanked here, in the three requests that answer it.  Each is a poll of
        the keyboard every client shares, and each transition in it is a key
        the user pressed.  The push side of the same fact is the XKB event
        allowlist in patch_event (XKB_EVENT_ALLOW).
        """
        if minor == 4:                                # XkbGetState
            # The live modifier/group/pointer-button state of the *shared*
            # keyboard, to any client that asks -- poll it and it is the
            # modifier logger QueryKeymap already answers empty, reached through
            # the extension.  The state fields run from offset 8 (mods) through
            # the ptrBtnState at 24-25; blank them and leave the device id,
            # sequence and length, so the reply stays well-formed.  The
            # modifiers a client needs for its *own* shift-click still arrive in
            # the event's state field; only the passive poll is closed (EV-6).
            return ("scrub", [(8, 18)]), "keyboard modifier-state poll"
        if minor == 12:                               # XkbGetIndicatorState
            # The whole reply past the header is one CARD32 of live indicator
            # state at offset 8: which locks are lit, right now, on the shared
            # keyboard.  This is XkbGetState's neighbour and was left readable
            # when that one was blanked -- measured answering 0x1 through the
            # proxy with Caps Lock engaged.
            return ("scrub", [(8, 4)]), "keyboard lock-state poll"
        if minor == 15:                               # XkbGetNamedIndicator
            # The same state, one named indicator at a time ("Caps Lock").
            # `on` at offset 13 is the live bit; `found` (12) and the map that
            # follows say what the indicator *is*, which is configuration, so
            # a client can still resolve a name to an indicator.
            return ("scrub", [(13, 1)]), "keyboard lock-state poll"
        if minor == 24 and len(body) < 4:             # XkbGetDeviceInfo
            # Too short to carry the facet mask the rule reads.  The server
            # would answer BadLength here anyway, and a request whose
            # arguments the policy could not read must not be forwarded on the
            # chance that they were harmless (fail closed, not open).
            return ((lambda seq: self.error(seq, BAD_ACCESS, major, minor)),
                    "unreadable device-info request")
        if minor == 24:                               # XkbGetDeviceInfo
            # The third route: ask for a device's LED feedbacks and the reply
            # carries their state.  The request says which facets it wants at
            # offset 2, so the indicator facets are stripped from it and the
            # rest -- the device list, the button actions -- is answered
            # normally, rather than refusing the whole request for one field.
            wanted = struct.unpack_from(self.endian + "H", body, 2)[0]
            if wanted & XKB_DEVICE_INDICATORS:
                patched = bytearray(body)
                struct.pack_into(self.endian + "H", patched, 2,
                                 wanted & ~XKB_DEVICE_INDICATORS)
                return (("rewrite", bytes(patched)),
                        "device indicator state")
        if minor in XKB_ALLOWED:
            return "allow", None
        return self.refuse_extension(major, minor, XKB_REPLIES,
                                     "writes shared keyboard state")

    def judge_randr(self, major, minor, body):
        """RANDR may be read, not written.

        Every application reads the monitor layout for DPI and placement, so
        the queries and SelectInput pass.  The configuration requests change
        the resolution, rotation, gamma or primary output of the screen the
        whole session shares -- a forwarded application can shrink or blank
        the desktop for everyone -- and are refused.
        """
        if minor in RANDR_ALLOWED:
            return "allow", None
        return self.refuse_extension(major, minor, RANDR_REPLIES,
                                     "reconfigures the shared screen")

    def judge_shape(self, major, minor, body):
        """SHAPE may reshape and read the client's own windows, not others'.

        Reshaping a foreign window makes another application's window
        invisible or click-through, which is the WINDOW_WRITE_REQUESTS attack
        arriving through an extension.  Reading one hands back its size and
        outline, which is the foreign window metadata GetGeometry is blanked
        to withhold (SH-1).  The writes name the window at offset 4 and expect
        no reply; the reads name it at offset 0 and do, so a foreign read is
        answered with a blank -- an unshaped window, no rectangles -- rather
        than an error, which would kill a simple Xlib client.
        """
        if minor not in SHAPE_ALLOWED:
            return self.refuse_extension(major, minor, SHAPE_REPLIES,
                                         "SHAPE request not on the allowlist")
        # Each of these tests the body length through names_foreign, so a
        # request too short to carry the field it is gated on is refused rather
        # than skipped -- see _names.
        if minor in SHAPE_WINDOW_WRITES:
            if self.names_foreign({minor: (4,)}, minor, body):
                return "silent", "reshapes a foreign window"
        if minor in SHAPE_SOURCE_DRAWABLES:
            # The source shape is read, not written, so this is the disclosure
            # half of the same request: gate it like CopyArea's source.
            if self.names_foreign({minor: (12,)}, minor, body):
                return "silent", "shape taken from a foreign drawable"
        if minor in SHAPE_WINDOW_READS:
            if self.names_foreign_window({minor: (0,)}, minor, body):
                return (lambda seq: self.reply(seq)), "foreign window shape"
            # An all-zero reply reads, for each of these, as a coherent "no
            # shape": QueryExtents' bounding-shaped is data byte 0, GetRects'
            # rectangle count is data word 0, InputSelected's enabled is the
            # header's second byte -- self.reply zeroes all of them.
        if minor == 6 and len(body) >= 4:             # ShapeSelectInput
            # Selecting ShapeNotify on a foreign window watches it reshape;
            # no reply, so a NoOp is answer enough.
            if self.is_foreign_window(self.word(body, 0)):
                return "silent", "watches a foreign window's shape"
        return "allow", None

    def _sync_watches_foreign_counter(self, minor, body):
        """True if a SYNC Await/CreateAlarm/ChangeAlarm names a foreign counter.

        Await (7) carries a list of 28-byte WAITCONDITIONs, each beginning with
        the counter it waits on.  CreateAlarm (8) and ChangeAlarm (9) carry a
        value-mask at offset 4 and a value-list at offset 8; the counter is the
        XSyncCACounter attribute (mask bit 0x1), and being the lowest bit it is
        the first value when present.  A client's own counters pass; the system
        IDLETIME counter is server-created and reads as foreign.
        """
        if minor == 7:                                # Await
            offset = 0
            while offset + 28 <= len(body):
                if self.is_foreign(self.word(body, offset)):
                    return True
                offset += 28
            return False
        if len(body) >= 12:                           # CreateAlarm / ChangeAlarm
            if self.word(body, 4) & 0x1:              # XSyncCACounter present
                return self.is_foreign(self.word(body, 8))
        return False

    def judge_sync(self, major, minor, body):
        """SYNC may drive the client's own counters, alarms and fences.

        The extension was passed whole on its major opcode.  It now gets the
        same minor-opcode allowlist the others have, and a foreign-resource gate
        on the requests that modify or destroy a sync object by id, or set
        another client's scheduling priority -- naming another client's counter,
        alarm or fence to reset, retrigger or destroy it, or lowering the whole
        session's priority, is a denial of service on it (no pixels or input
        are involved, so this is integrity/availability, not disclosure).  The
        Create requests name a *new* id in the client's own range and are not
        gated -- except CreateFence, whose first field is a drawable and whose
        new id is second.  Await and CreateAlarm/ChangeAlarm *watch* a counter,
        and watching the server's system IDLETIME counter is an idle/activity
        side channel (the timing twin of the QueryCounter read now blanked), so
        those are refused when the counter they name is foreign.
        """
        if minor not in SYNC_ALLOWED:
            return self.refuse_extension(major, minor, SYNC_REPLIES,
                                         "SYNC request not on the allowlist")
        if minor == 14 and len(body) >= 4:            # CreateFence(drawable, fid)
            # A drawable here only names a screen, so a root passes and another
            # client's window does not -- the SCREEN_REFERENCE_REQUESTS rule,
            # arriving through an extension.
            if self.is_foreign_window(self.word(body, 0)):
                return "silent", "fence on a foreign drawable"
            return "allow", None
        if minor in (7, 8, 9) and self._sync_watches_foreign_counter(minor, body):
            # Await(7)/CreateAlarm(8)/ChangeAlarm(9) on a foreign counter -- the
            # system IDLETIME counter above all -- turns idle time into a timing
            # or event side channel about the whole session.  None expects a
            # reply, so a NoOp is refusal enough.
            return "silent", "watches a foreign sync counter (idle-time channel)"
        if self.names_foreign(SYNC_FOREIGN_READS, minor, body):
            # Reads a foreign sync object's state (IDLETIME the notable one);
            # answered blank rather than truthfully, since it expects a reply.
            return ((lambda seq: self.reply(seq)),
                    "reads another client's or a system sync object")
        if self.names_foreign(SYNC_FOREIGN, minor, body):
            return "silent", "SYNC operation on another client's resource"
        return "allow", None

    def judge_dbe(self, major, minor, body):
        """DOUBLE-BUFFER may back-buffer the client's own windows, not others'.

        A back buffer is allocated against a window and named by its own id.
        Allocating one against a foreign window, or swapping/deallocating/
        reading one that is another client's, reaches into that client's
        drawing -- the WINDOW_WRITE_REQUESTS / FOREIGN_RESOURCE shape, in an
        extension.  (A back buffer starts blank and is not a copy of the front
        buffer, so this is not screen capture.)  SwapBuffers names a variable
        list of windows and is walked separately.
        """
        if minor not in DBE_ALLOWED:
            return self.refuse_extension(major, minor, DBE_REPLIES,
                                         "DOUBLE-BUFFER request not on the "
                                         "allowlist")
        if minor == 1 and len(body) >= 4:             # AllocateBackBuffer(window)
            if self.is_foreign(self.word(body, 0)):
                return "silent", "back buffer on a foreign window"
            return "allow", None
        if minor == 2 and len(body) >= 4:             # DeallocateBackBuffer(buffer)
            if self.is_foreign(self.word(body, 0)):
                return "silent", "deallocates a foreign back buffer"
            return "allow", None
        if minor == 7 and len(body) >= 4:             # GetBackBufferAttributes
            if self.is_foreign(self.word(body, 0)):
                # reply names the buffer's window; a blank one (window None) is
                # a coherent answer, and an error would kill a simple client
                return (lambda seq: self.reply(seq)), \
                    "foreign back buffer attributes"
            return "allow", None
        if minor == 3 and len(body) >= 4:             # SwapBuffers(list)
            # body: n (CARD32), then n * (window(4), swap-action(1), pad(3))
            count = self.word(body, 0)
            for i in range(count):
                offset = 4 + i * 8
                if len(body) < offset + 4:
                    break
                if self.is_foreign(self.word(body, offset)):
                    return "silent", "swaps a foreign window's buffers"
            return "allow", None
        return "allow", None

    def _judge_minor_allowlist(self, major, minor, allowed, replies, label):
        """The whole policy for an extension with no foreign-resource surface:
        a known minor passes, an unknown one is refused (answered only if it
        expects a reply, per refuse_extension).  This is what makes 'unknown
        means refused' hold inside the read-only extensions too."""
        if minor in allowed:
            return "allow", None
        return self.refuse_extension(major, minor, replies,
                                     "%s request not on the allowlist" % label)

    def judge_xinerama(self, major, minor, body):
        """XINERAMA: read-only monitor-layout queries, the class RANDR answers.
        Screen geometry is not secret and none of these names a foreign
        resource, so the minor allowlist is the whole policy."""
        return self._judge_minor_allowlist(major, minor, XINERAMA_ALLOWED,
                                           XINERAMA_REPLIES, "XINERAMA")

    def judge_xcmisc(self, major, minor, body):
        """XC-MISC hands the client more of its *own* XIDs; no foreign surface."""
        return self._judge_minor_allowlist(major, minor, XCMISC_ALLOWED,
                                           XCMISC_REPLIES, "XC-MISC")

    def judge_generic_event(self, major, minor, body):
        """Generic Event Extension is a version handshake (QueryVersion only);
        the events it carries are gated by whichever extension selects them."""
        return self._judge_minor_allowlist(major, minor, GENERIC_EVENT_ALLOWED,
                                           GENERIC_EVENT_REPLIES,
                                           "Generic Event Extension")

    def judge_big_requests(self, major, minor, body):
        """BIG-REQUESTS is one request, BigReqEnable; the length semantics are
        handled in the relay, so here it is just an allowlist of that minor."""
        return self._judge_minor_allowlist(major, minor, BIG_REQUESTS_ALLOWED,
                                           BIG_REQUESTS_REPLIES, "BIG-REQUESTS")

    def judge_xinput(self, major, minor, body):
        """XInput is allowed for drawing and devices, but not as an input tap.

        The extension reaches the same keystrokes XTEST and RECORD are denied
        for; a raw-event selection on the root is a working keylogger.  So
        the taps, grabs, focus and warps that name a window the
        client does not own are refused, the same shape of check the core
        protocol already gets, while everything on the client's own windows
        passes.
        """
        if minor not in XI_ALLOWED:
            return self.refuse_extension(
                major, minor, XI_REPLIES,
                "XInput request not on the allowlist")
        if minor == 21 and len(body) >= 4:            # XI1 SetDeviceFocus
            # the XInput1 twin of XISetFocus, which was already scoped
            if self.is_foreign(self.word(body, 0)):
                return "silent", "XInput focus to a foreign window"
            return "allow", None
        if minor == 42 and len(body) >= 4:            # XIChangeCursor
            if self.is_foreign(self.word(body, 0)):
                return "silent", "changes the cursor of a foreign window"
            return "allow", None
        if minor == 22:                               # XI1 GetFeedbackControl
            # The keyboard feedback record carries `led_mask` and `led_values`
            # -- the lock state the XKB polls and the core LED mask are now
            # blanked for, listed per device instead of per server.  The
            # record sits in a variable-length list, so this cannot be a fixed
            # reply offset like the others; blank_feedback_leds walks the list.
            # Measured with Caps Lock engaged: the virtual core keyboard's
            # feedback answers led_mask 0x1 direct and 0x0 through the proxy.
            return "feedback", "keyboard lock state per device"
        if minor in (20, 50):                         # XI1 GetDeviceFocus /
            #                                           XI2 XIGetFocus
            # XI-1: the XInput twins of GetInputFocus (OF-1).  Both replies
            # name whichever window holds focus, another client's included, so
            # polling either is the same focus trace GetInputFocus was pulled
            # from SAFE_CORE for.  Scope them the same way -- blank the focus
            # window (offset 8 in both replies) only when it is foreign, so
            # "do I have focus?" still answers truthfully.
            return ("scrub-foreign", ([8], 0)), "foreign focus window"
        if minor in XI_FOREIGN_WINDOW_READS:
            # Reads about the window rather than about the asking client: the
            # event classes selected on it (7), its do-not-propagate list (9),
            # the pointer device of the client owning it (45).  Each reply
            # carries its count or flag in the first data word, so a blank
            # reply reads as an empty, coherent answer rather than an error.
            if self.names_foreign_window({minor: (0,)}, minor, body):
                return (lambda seq: self.reply(seq)), \
                    "foreign window's input wiring"
        if minor == 8 and len(body) >= 4:             # XI1 ChangeDeviceDontPropagateList
            # Rewrites the do-not-propagate list on a window; on a foreign one
            # it alters another client's event routing.  No reply.
            if self.is_foreign_window(self.word(body, 0)):
                return "silent", "changes a foreign window's event routing"
            return "allow", None
        if minor == 46 and len(body) >= 8:            # XISelectEvents
            if self.is_foreign(self.word(body, 0)) and \
                    self._mask_is_input_tap(body):
                return ("silent",
                        "XInput input/crossing/focus tap on a foreign window")
            return "allow", None
        if minor == 40 and len(body) >= 4:            # XIQueryPointer
            # the XInput twin of QueryPointer: the modifier/group and button
            # state past offset 36 is always blanked, and the global position
            # is bounded to the client's own window the same way the core
            # request is (FP1616 coordinates rather than INT16).
            size = self._pointer_bound(self.word(body, 0))
            return ("pointer", (size, "xi")), "XInput pointer position and input-state"
        if minor == 6 and len(body) >= 4:             # XI1 SelectExtensionEvent
            if self.is_foreign(self.word(body, 0)):
                return "silent", "XInput event tap on a foreign window"
            return "allow", None
        if minor == 13 and len(body) >= 4:            # XI1 GrabDevice
            if self.is_foreign(self.word(body, 0)):
                return ((lambda seq: self.reply(seq, bytes([1]))),
                        "XInput grab on a foreign window")
            # The XInput1 spelling of the same grab, bounded the same way:
            # the keys it would steal are withheld in the event stream.
            self.keyboard_grabbed = True
            return "allow", None
        if minor == 14:                               # XI1 UngrabDevice
            self.keyboard_grabbed = False
            return "allow", None
        if minor in (15, 17) and len(body) >= 4:      # XI1 GrabDeviceKey/Button
            # A passive device grab of a key or button on a foreign window is
            # a targeted tap for that key: the XInput1 route to the same thing
            # XISelectEvents is refused for above.
            if self.is_foreign(self.word(body, 0)):
                return "silent", "XInput passive grab on a foreign window"
            return "allow", None
        if minor == 49 and len(body) >= 4:            # XISetFocus
            if self.is_foreign(self.word(body, 0)):
                return "silent", "XInput focus to a foreign window"
            return "allow", None
        if minor == 41 and len(body) >= 8:            # XIWarpPointer
            if self.is_foreign(self.word(body, 4)):
                return "silent", "XInput pointer warp into a foreign window"
            return "allow", None
        if minor == 51 and len(body) >= 4:            # XIGrabDevice
            if self.is_foreign(self.word(body, 0)):
                # reply carries a status byte at offset 8; 1 == AlreadyGrabbed
                return ((lambda seq: self.reply(seq, bytes([1]))),
                        "XInput grab on a foreign window")
            # The XInput2 spelling, and the one that matters: a modern
            # toolkit grabs through XI2, not through GrabKeyboard.  Allowed
            # like the core one, and bounded the same way -- GTK asks for the
            # pointer and the keyboard together here, so refusing it stopped
            # menus opening at all (measured against gedit: no context menu,
            # where without the proxy one appeared at the pointer).
            self.keyboard_grabbed = True
            return "allow", None
        if minor == 52:                               # XI2 XIUngrabDevice
            # Cleared on the ungrab as well as set on the grab: a toolkit takes
            # the keyboard to open a menu and gives it back when the menu
            # closes, and a flag that only ever went one way would leave an
            # ordinary application permanently marked as holding the keyboard.
            self.keyboard_grabbed = False
            return "allow", None
        if minor == 61 and len(body) >= 4:            # XIBarrierReleasePointer
            # num_barriers at offset 0, then twelve-byte entries carrying the
            # barrier id at +4.  Releasing another client's pointer barrier
            # lets the pointer cross a boundary that client put up -- the
            # foreign-resource nuisance SYNC and DOUBLE-BUFFER are gated for.
            for index in range(self.word(body, 0)):
                offset = 8 + index * 12
                if len(body) < offset + 4:
                    break
                if self.is_foreign(self.word(body, offset)):
                    return "silent", "releases a foreign pointer barrier"
            return "allow", None
        if minor == 54 and len(body) >= 8:            # XIPassiveGrabDevice
            if self.is_foreign(self.word(body, 4)):
                # reply is a (possibly empty) list of rejected modifiers; an
                # empty one is a plausible answer the client can absorb
                return ((lambda seq: self.reply(seq)),
                        "XInput passive grab on a foreign window")
            return "allow", None
        return "allow", None

    def judge_render(self, major, minor, body):
        """RENDER draws natively, but must not build a Picture of the screen.

        A Picture wraps a drawable; composited into a pixmap the client owns,
        it turns GetImage on that pixmap -- which the policy rightly allows --
        into a screen capture.  Blocking the Picture at
        creation, when its drawable is foreign, closes the vector at source;
        every later Composite can only read Pictures that were allowed.
        """
        if minor not in RENDER_ALLOWED:
            return self.refuse_extension(major, minor, RENDER_REPLIES,
                                         "RENDER request not on the allowlist")
        if minor == 4 and len(body) >= 8:             # RenderCreatePicture
            if self.is_foreign(self.word(body, 4)):
                return "silent", "RENDER picture of a foreign drawable"
            return "allow", None
        if self.names_foreign(RENDER_FOREIGN, minor, body):
            return "silent", "RENDER names another client's resource"
        return "allow", None

    def judge_xfixes(self, major, minor, body):
        """XFIXES is allowed, except where it watches or reaches into the session.

        The cursor requests come first because they are refused for what they
        are, not merely for being off a list: GetCursorImage returns the pixels
        and position of the one cursor everybody shares, and SelectCursorInput
        reports every time its image changes anywhere on the server -- a coarse
        account of what the user is doing, next to the pointer position that is
        already the acknowledged residual.  After that, an unrecognised request
        is refused, SelectSelectionInput is checked against the gated
        selections, and everything naming a region, graphics context, picture,
        cursor or window is checked for whose it is.
        """
        if minor == 3:                                # SelectCursorInput
            return "silent", "cursor-change monitor"
        if minor in (4, 25):                          # GetCursorImage[AndName]
            return ((lambda seq: self._blank_cursor(seq, named=minor == 25)),
                    "cursor image and position")
        if minor == 29:                               # HideCursor
            # Hiding the pointer everyone shares is a plausible step in
            # dressing up a spoofed window; ShowCursor is left alone.
            return "silent", "hides the shared cursor"
        if minor not in XFIXES_ALLOWED:
            return self.refuse_extension(major, minor, XFIXES_REPLIES,
                                         "XFIXES request not on the allowlist")
        if minor == 2 and len(body) >= 8:             # SelectSelectionInput
            if self.is_gated_selection(self.word(body, 4)):
                return "silent", "XFIXES snoop on a gated selection"
            return "allow", None
        if minor == 21 and len(body) >= 4:            # SetWindowShapeRegion
            if self.is_foreign(self.word(body, 0)):
                return "silent", "reshapes a foreign window"
            # The region is at offset 12, and only the window was ever checked.
            # Shaping the client's *own* window with another client's region
            # and then reading that window's shape back -- ShapeQueryExtents on
            # a window you own is allowed -- reports the foreign region's
            # extents, which is what gating CreateRegionFromWindow was for.
            if len(body) >= 16 and self.is_foreign(self.word(body, 12)):
                return "silent", "shapes a window with a foreign region"
            return "allow", None
        if self.names_foreign(XFIXES_FOREIGN, minor, body):
            return "silent", "XFIXES names another client's resource"
        return "allow", None

    # -- enforcement -------------------------------------------------------

    def sentinel(self, opcode, minor, verdict, reason):
        """Log an operation the first time this connection meets it.

        The hot path is a single set-membership test on a cheap integer key,
        so an already-seen operation costs nothing here -- no string built, no
        counter touched.  Only a genuinely new one pays for its name and the
        one-line note to stderr and the --log file, naming the process behind
        it: the claimed identity (which the client controls) and its
        unforgeable local credentials.
        """
        # scrub forwards the real request (with a blanked reply), so it reads
        # as allowed here rather than blocked.
        passed = verdict in ("allow", "feedback") or (
            isinstance(verdict, tuple)
            and verdict[0] in ("scrub", "scrub-foreign", "pointer"))
        # The verdict is part of the key, not just the payload.  Most requests
        # that carry a window are allowed on the client's own and refused on a
        # foreign one, so keying on the name alone means whichever came first
        # is the only outcome ever reported -- an over-block hidden behind an
        # earlier allow of the same request, which is precisely what the log
        # exists to surface.  One line per (operation, verdict) still costs a
        # single set-membership test on the hot path.
        seen_key = (opcode, passed) if opcode < 128 else (opcode, minor, passed)
        if seen_key in self.seen:
            return
        self.seen.add(seen_key)
        key = self.request_key(opcode, minor)
        if self.profile.note_first_seen((key, passed), self.describe(),
                                        self.peer_label(), passed, reason):
            line = ("new operation: %-40s %-8s %s [%s]"
                    % (key, "allowed" if passed else "blocked",
                       self.describe(), self.peer_label()))
            if self.alert_new:
                print(line, file=sys.stderr)
            self.profile.log_line(line)
        if not passed and reason in (GATE_REFUSED, GATE_OWNER_REFUSED) \
                and self.gate_mode == "deny" and self.profile.note_gate_hint():
            if self.alert_new:
                print(GATE_HINT, file=sys.stderr)
            self.profile.log_line(GATE_HINT)

    def forward(self, opcode, minor, head, body):
        if opcode == 18:                             # ChangeProperty
            try:
                self.note_identity(body)
            except (struct.error, IndexError):
                pass
        try:
            verdict, reason = self.judge(opcode, minor, body)
        except (struct.error, IndexError, UnicodeDecodeError):
            # The policy could not parse the request, so it does not know what
            # the request does.  That is precisely when it must not pass: a
            # body too short for the field a rule reads would otherwise skip
            # the rule and be forwarded, which is a fail-open at the one point
            # the whole design rests on.  Block it, and log it under its own
            # reason so an unparsable request is distinguishable in the log
            # from one the policy deliberately allowed.
            verdict, reason = "block", "unparsable request"

        # A verdict that ends in a question to the user is logged *after* the
        # answer, not before it: "ask" is not an outcome, and recording it as
        # one made the log say `core:ConvertSelection blocked` about a paste
        # the user had just allowed.  Measured end to end on a nested desktop,
        # where the clipboard arrived in the filtered application while the
        # operation log denied that it had.  The log is the record of what the
        # policy did; it does not get to be wrong about that.
        if verdict not in ("ask", "ask-owner"):
            self.sentinel(opcode, minor, verdict, reason)

        if verdict == "allow":
            if opcode == 99 and self.enforce:        # ListExtensions
                with self.lock:
                    self.listings.add(self.sequence)
            self.server.sendall(head + body)
            return

        if isinstance(verdict, tuple) and verdict[0] == "scrub-foreign":
            if self.enforce:
                with self.lock:
                    self.reply_foreign[self.sequence] = verdict[1]
            self.server.sendall(head + body)
            return

        if isinstance(verdict, tuple) and verdict[0] == "scrub":
            # Forward the real request; when enforcing, register the reply
            # fields to blank so substitution() edits the answer on the way
            # back.  In dry-run the request just passes, unblanked.
            if self.enforce:
                with self.lock:
                    self.reply_scrubs[self.sequence] = verdict[1]
            self.server.sendall(head + body)
            return

        if verdict == "feedback":
            # Forward the real GetFeedbackControl and blank the LED words of
            # every keyboard feedback in the reply on the way back.
            if self.enforce:
                with self.lock:
                    self.reply_leds.add(self.sequence)
            self.server.sendall(head + body)
            return

        if isinstance(verdict, tuple) and verdict[0] == "rewrite":
            # The request is forwarded with a field removed rather than
            # refused: it asked for several things at once and only one of
            # them is denied, so the client gets a well-formed answer to the
            # rest.  Dry-run forwards the original.  The log still counts this
            # as a refusal, because something was taken out of it.
            self.server.sendall(head + (verdict[1] if self.enforce else body))
            return

        if isinstance(verdict, tuple) and verdict[0] == "pointer":
            # Forward the real QueryPointer; when enforcing, register the
            # queried own-window's size so substitution() can decide, from the
            # reply, whether the pointer is actually over that window and blank
            # the global position when it is not.
            if self.enforce:
                with self.lock:
                    self.reply_pointer[self.sequence] = verdict[1]
            self.server.sendall(head + body)
            return

        if isinstance(verdict, tuple) and verdict[0] == "fullscreen":
            # A window would take over the whole screen: --gate allow lets it,
            # --gate ask puts it to the user, --gate deny (default) refuses.  A
            # refusal forwards the neutralised request (override-redirect
            # stripped / fullscreen atom removed), or a NoOp when there is
            # nothing left to send.  Dry-run forwards the original untouched.
            deny_body = verdict[1]
            if not self.enforce or self._fullscreen_allowed():
                self.server.sendall(head + body)
            elif deny_body is not None:
                self.server.sendall(head + deny_body)
            else:
                self.server.sendall(
                    struct.pack(self.endian + "BBH", NOOP, 0, 1))
            return

        if not self.enforce:
            self.server.sendall(head + body)
            if verdict == "hide-extension":
                pass                    # dry run: let the client see the truth
            return

        if verdict == "ask-owner":
            selection = self.atom_name(self.word(body, 4)) or "selection"
            if self.gate.decide(self.conn_token, self.describe(), selection,
                                "ownership", self.peer_label(), action="own"):
                self.sentinel(opcode, minor, "allow", "the user allowed it")
                self.server.sendall(head + body)
                return
            self.sentinel(opcode, minor, "silent", GATE_OWNER_REFUSED)
            # Refused: SetSelectionOwner expects no reply, so dropping it
            # leaves the client believing nothing and the real owner in place.
            verdict = "silent"

        if verdict == "ask":
            selection = self.atom_name(self.word(body, 4)) or "selection"
            target = self.atom_name(self.word(body, 8)) or "?"
            if self.gate.decide(self.conn_token, self.describe(),
                                selection, target, self.peer_label()):
                self.profile.note_allowed_paste(self.describe(), selection)
                self.sentinel(opcode, minor, "allow", "the user allowed it")
                self.server.sendall(head + body)
                return
            self.sentinel(opcode, minor, "gate", GATE_REFUSED)
            verdict = "gate"

        if verdict == "gate":
            # Key the record on (requestor, target), not (requestor,
            # property): a refused conversion comes back with property = None,
            # so a property-keyed record could never match on the way out and
            # the SelectionNotify went unpatched.  The target is
            # preserved end to end, since only the selection atom is rewritten.
            selection = self.word(body, 4)
            requestor, target = self.word(body, 0), self.word(body, 8)
            with self.lock:
                self.gated[(requestor, target)] = selection
            patched = bytearray(body)
            struct.pack_into(self.endian + "I", patched, 4, UNOWNED_ATOM)
            self.server.sendall(head + bytes(patched))
            return

        if verdict == "hide-extension":
            # Let the real QueryExtension through so we learn the opcode
            # the server assigned, then lie about it to the client.
            with self.lock:
                self.query_denied[self.sequence] = True
            self.server.sendall(head + body)
            return

        if verdict in ("silent", "block") and opcode not in REPLY_REQUESTS:
            self.server.sendall(struct.pack(self.endian + "BBH", NOOP, 0, 1))
            return

        # Anything else needs an answer: send a harmless request that
        # replies, and swap its reply for ours when it comes back.  A blocked
        # or silently-refused request that expects a reply gets an error,
        # which consumes its sequence number and every toolkit handles.
        answer = verdict if callable(verdict) else \
            (lambda seq: self.error(seq, BAD_ACCESS, opcode, minor))
        with self.lock:
            self.substitutions[self.sequence] = answer
        self.server.sendall(
            struct.pack(self.endian + "BBH", GET_INPUT_FOCUS, 0, 1))

    def filter_extension_list(self, head, body):
        """Keep only allowlisted extensions in a ListExtensions reply.

        QueryExtension already reports everything else absent and their
        opcodes are blocked, so this changes nothing about what a client can
        do -- but leaving the names visible makes every obvious check report
        the opposite of the truth.
        """
        names, offset = [], 0
        for _ in range(head[1]):
            if offset >= len(body):
                break
            size = body[offset]
            names.append(body[offset + 1:offset + 1 + size])
            offset += 1 + size
        kept = [n for n in names
                if n.decode("latin-1", "replace") in ALLOWED_EXTENSIONS]
        packed = b"".join(bytes([len(n)]) + n for n in kept)
        packed += b"\0" * pad4(len(packed))
        patched = bytearray(head)
        patched[1] = len(kept)
        struct.pack_into(self.endian + "I", patched, 4, len(packed) // 4)
        return bytes(patched) + packed

    def scrub_reply(self, head, body, ranges):
        """Blank byte ranges of the real reply -- the 'scrub' strategy.

        Each range is (offset, length); length None means "to the end".
        The offset counts from the start of the reply, so the fixed 32-byte
        head and any body are one buffer here.  This is how a request is
        answered truthfully except for the fields that would leak input
        state -- the pointer's button/modifier mask, say.
        """
        buffer = bytearray(head + body)
        for offset, length in ranges:
            end = len(buffer) if length is None else offset + length
            for i in range(offset, min(end, len(buffer))):
                buffer[i] = 0
        return bytes(buffer)

    def scrub_foreign_windows(self, head, body, offsets, stand_in=0):
        """Replace 4-byte window fields of a reply, but only where foreign.

        The conditional is the point.  Blanking unconditionally would answer
        "nobody has the focus" even when the client itself does, and a toolkit
        that asks whether it holds focus would believe it does not.  Answering
        truthfully about the client's own window and None about anyone else's
        is the same isolate-rather-than-block shape GetGeometry and QueryTree
        already use: the client is not lied to about itself, it is told
        nothing about others.

        `stand_in` is what a foreign id becomes.  It is None (0) wherever
        "nobody" is a truthful-enough answer -- the focus window -- and a
        constant invalid id where None would be read as *no such thing exists*
        and break the client: GetSelectionOwner, where "nobody owns the
        clipboard" means "there is nothing to paste" (SELECTION_OWNER_STANDIN).
        Either way the reply carries no foreign window id and no change to
        follow when the real one changes.
        """
        buffer = bytearray(head + body)
        for offset in offsets:
            if offset + 4 <= len(buffer):
                window = struct.unpack_from(self.endian + "I", buffer, offset)[0]
                if window and self.is_foreign_window(window):
                    struct.pack_into(self.endian + "I", buffer, offset, stand_in)
        return bytes(buffer)

    # QueryPointer reply layouts: where the fields the bounding needs live, and
    # which bytes name the global position that leaks when the pointer is not
    # over the client's own window.  The core reply is INT16 coordinates; the
    # XInput2 reply is FP1616 (16.16 fixed point), so its integer part is the
    # high half.  `always` is the input-state tail blanked unconditionally (the
    # button/modifier mask), as it was before this bounding was added.
    POINTER_CORE = {
        "same_screen": 1, "win_x": (20, "i16"), "win_y": (22, "i16"),
        "position": [(1, 1), (12, 12)],   # same_screen byte; child + both coord pairs
        "always": [(24, 2)],
    }
    POINTER_XI = {
        "same_screen": 32, "win_x": (24, "fp1616"), "win_y": (28, "fp1616"),
        "position": [(12, 20), (32, 1)],  # child + root/win coords; same_screen byte
        "always": [(36, None)],
    }
    _POINTER_LAYOUTS = {"core": POINTER_CORE, "xi": POINTER_XI}

    def _pointer_coord(self, buffer, spec):
        offset, kind = spec
        value = struct.unpack_from(self.endian + "h", buffer, offset)[0] \
            if kind == "i16" else \
            struct.unpack_from(self.endian + "i", buffer, offset)[0] >> 16
        return value

    def bound_pointer_reply(self, head, body, size, layout_name):
        """Blank a QueryPointer reply's global position unless the pointer is
        provably over the client's own window.

        The reply always carries the global pointer position, so a client can
        poll QueryPointer over a window it owns and read the pointer wherever it
        is on the screen -- a position trace of the whole session out of a
        request that names only its own window.  The fundamental part is
        irreducible: while the pointer is genuinely over the client's window it
        is entitled to the position (it could reconstruct it from its own window
        origin anyway).  The reducible part is the position while the pointer is
        elsewhere, and that is what this blanks.

        The decision is made from the reply itself: the window-relative
        coordinates against the window's known size, plus same_screen.  A
        position is kept only when it is provably inside -- same_screen set and
        the relative coordinates within [0, width) x [0, height).

        `size` is None whenever the caller could not establish that the query
        names a mapped window of this application (see _pointer_bound), and
        None **blanks**.  It used to mean the opposite -- "not one we tracked,
        so leave it alone" -- and that default was the twelfth pass's finding:
        the root window is not tracked, so `QueryPointer(root)`, the ordinary
        way every toolkit asks where the mouse is, walked straight past the
        bound and returned the true global position, as did a query about a
        window created huge and never mapped.  Proving the pointer is outside
        is not the test; proving it is inside is.

        The residual is an own window a foreign window occludes: the
        coordinates read in-bounds while the pointer is really over the
        occluder.
        """
        layout = self._POINTER_LAYOUTS[layout_name]
        buffer = bytearray(head + body)
        for offset, length in layout["always"]:
            end = len(buffer) if length is None else offset + length
            for i in range(offset, min(end, len(buffer))):
                buffer[i] = 0
        # Fail closed: the position survives only if this reply proves the
        # pointer is inside a mapped own window.  Anything else -- an unknown
        # window, an unmapped one, a reply too short to carry the fields the
        # test reads -- is blanked.
        blank = True
        if size is not None and len(buffer) > max(
                layout["win_y"][0] + 4, layout["same_screen"]):
            same_screen = buffer[layout["same_screen"]]
            win_x = self._pointer_coord(buffer, layout["win_x"])
            win_y = self._pointer_coord(buffer, layout["win_y"])
            width, height = size
            inside = (bool(same_screen) and width and height
                      and 0 <= win_x < width and 0 <= win_y < height)
            blank = not inside
        if blank:
            for offset, length in layout["position"]:
                for i in range(offset, min(offset + length, len(buffer))):
                    buffer[i] = 0
        return bytes(buffer)

    #: The XInput1 feedback classes, and the layout of the one that carries
    #: lock state.  Every feedback in a GetFeedbackControl reply begins with
    #: class, id and its own length, so the list can be walked without knowing
    #: any other class: read the length, act if the class is the keyboard's,
    #: step on.  KbdFeedbackClass is 0, and its led_mask and led_values are the
    #: two words at offset 8 of the record.
    KBD_FEEDBACK_CLASS = 0
    KBD_FEEDBACK_LEDS = (8, 8)                   # (offset, bytes) in the record

    def blank_feedback_leds(self, head, body):
        """Zero the LED words of every keyboard feedback in the reply.

        The rest of each record -- the bell pitch and duration, the auto-repeat
        map, the other feedback classes -- is configuration and is answered
        truthfully.  A record whose length is nonsense stops the walk rather
        than looping: a malformed reply must not cost more than one pass.
        """
        buffer = bytearray(head + body)
        count = struct.unpack_from(self.endian + "H", buffer, 8)[0]
        offset = 32
        for _ in range(count):
            if offset + 4 > len(buffer):
                break
            length = struct.unpack_from(self.endian + "H", buffer, offset + 2)[0]
            if length < 4:
                break
            if buffer[offset] == self.KBD_FEEDBACK_CLASS:
                start, size = self.KBD_FEEDBACK_LEDS
                for i in range(offset + start,
                               min(offset + start + size, len(buffer))):
                    buffer[i] = 0
            offset += length
        return bytes(buffer)

    def discard_sequence(self, sequence):
        """The request at this sequence failed, so nothing will claim what the
        policy registered for its reply.  Every table keyed by sequence is
        dropped together -- one place to add to, rather than a rule per table
        that the next kind of substitution has to remember."""
        with self.lock:
            for table in (self.substitutions, self.reply_scrubs,
                          self.reply_foreign, self.reply_pointer,
                          self.query_denied):
                table.pop(sequence, None)
            self.reply_leds.discard(sequence)
            self.listings.discard(sequence)

    def _bound_event_position(self, head):
        """Blank the global position in a pointer event that proves the pointer
        is not over the window the event was reported against.

        The event-side twin of bound_pointer_reply, and the answer to a pointer
        grab: under one, the server reports events for the whole screen against
        the grab window, so the window-relative coordinates fall outside the
        window's tracked size exactly when the pointer is somebody else's
        business.  A window whose size the policy does not know proves nothing,
        so its events are bounded too -- the same fail-closed default the
        twelfth pass gave the reply side.
        """
        window = self.word(head, 12)
        state = self.profile.window_state(window)
        event_x, event_y = struct.unpack_from(self.endian + "hh", head, 24)
        inside = bool(state) and state[3] \
            and 0 <= event_x < state[0] and 0 <= event_y < state[1]
        if inside:
            return None
        patched = bytearray(head)
        struct.pack_into(self.endian + "I", patched, 16, 0)      # child
        struct.pack_into(self.endian + "hh", patched, 20, 0, 0)  # root x, y
        struct.pack_into(self.endian + "H", patched, 28, 0)      # modifiers
        return bytes(patched)

    def substitution(self, sequence, head, body):
        with self.lock:
            answer = self.substitutions.pop(sequence, None)
            scrub = self.reply_scrubs.pop(sequence, None)
            foreign = self.reply_foreign.pop(sequence, None)
            pointer = self.reply_pointer.pop(sequence, None)
            leds = sequence in self.reply_leds
            self.reply_leds.discard(sequence)
            hidden = self.query_denied.pop(sequence, None)
            listing = sequence in self.listings
            self.listings.discard(sequence)
        if listing:
            try:
                return self.filter_extension_list(head, body)
            except (struct.error, IndexError):
                return None
        if answer is not None:
            return answer(sequence)
        if scrub is not None:
            try:
                return self.scrub_reply(head, body, scrub)
            except (struct.error, IndexError):
                return None
        if foreign is not None:
            try:
                return self.scrub_foreign_windows(head, body, *foreign)
            except (struct.error, IndexError):
                return None
        if leds:
            try:
                return self.blank_feedback_leds(head, body)
            except (struct.error, IndexError):
                return None
        if pointer is not None:
            try:
                return self.bound_pointer_reply(head, body, *pointer)
            except (struct.error, IndexError):
                return None
        if hidden:
            self.denied_opcodes.add(head[9])
            return self.reply(sequence)          # present = 0
        return None

    def patch_event(self, head):
        code = head[0] & 0x7F
        if code == 30 and len(head) >= 28:       # SelectionRequest
            # EV-7.  Learn which foreign windows a paste-out may write to only
            # from a *server-generated* SelectionRequest -- one the server made
            # because another client really asked this one for a selection.  A
            # SelectionRequest with the 0x80 "sent via SendEvent" bit set was
            # forged by the client and delivered to its own window (SendEvent
            # to a window it created is allowed), and trusting it let the
            # client whitelist any window for foreign ChangeProperty and
            # SelectionNotify and reopen the EV-3 PropertyNotify channel.  A
            # genuine one always has the bit clear, so this leaves outbound
            # paste untouched and stops the forgery teaching the policy
            # anything.
            if head[0] & 0x80:
                return None
            self.grant_selection(self.word(head, 12), self.word(head, 24))
            return None

        # --dry-run promises to report what the policy would refuse and refuse
        # nothing, and the request and reply paths keep that promise -- a
        # substitution is only registered `if self.enforce`.  This path used to
        # keep it with a blanket early return here, which was right about the
        # refusing and wrong about the reporting: skipping the arms altogether
        # meant a dry run never worked out *which* events it would have
        # withheld, so the drops the twenty-sixth pass made visible were
        # visible only in the mode that also performed them.  Now every arm
        # runs and every decision is logged; the flag is consulted where the
        # change is made -- withhold() for a refusal, and a guard on each
        # rewrite below -- so a dry run is still byte-for-byte an unfiltered
        # one on the wire.  Learning from an event happens either way.

        if code == 11:                           # KeymapNotify
            # EV-5.  KeymapNotify carries a 32-byte bitmap of every key
            # physically down -- the same data QueryKeymap returns, which is
            # already answered as "no keys down" -- and the server sends it
            # after every EnterNotify and FocusIn on a window that selected
            # KeymapState.  Selecting it on a foreign window is refused, but
            # on the client's own window it is allowed, and the bitmap is
            # global either way.
            #
            # That is pollable, not merely sampled: QueryPointer over its own
            # window gives the client the pointer position, moving its own
            # window under that position is its own tree, and the pointer
            # entering generates another EnterNotify.  Repeat for a keylogger
            # at a rate of the client's choosing, out of allowed requests.
            #
            # Zeroed rather than dropped: a client that selected the mask is
            # expecting the event after a focus change, and withholding it
            # could leave one waiting.  This is the QueryKeymap substitution
            # applied to an event.  KeymapNotify is the one core event with
            # neither a window nor a sequence number -- the code byte, then 31
            # bytes of bitmap -- so there is nothing else in it to preserve.
            return (bytes(head[:1]) + b"\0" * 31) if self.enforce else None

        xkb_base = self.profile.event_base("XKEYBOARD")
        if xkb_base is not None and code == xkb_base and len(head) >= 2:
            # XKEYBOARD delivers all its events under one type byte, with the
            # XKB event subtype in the second byte, and XkbSelectEvents asks
            # for them wholesale -- it is passed without inspection because
            # toolkits need XkbNewKeyboardNotify (0) and XkbMapNotify (1).
            # This was a block-list (drop XkbStateNotify, pass the rest, EV-6)
            # and is now the allowlist those two are the whole of: the same
            # inversion the tenth pass made everywhere else, made here because
            # the block-list had left the *lock* state streaming out beside the
            # modifier state it dropped -- IndicatorStateNotify (4) and
            # ExtensionDeviceNotify (11), both measured arriving through the
            # proxy on a Caps Lock press.  Withholding is safe the way the
            # KeymapNotify zeroing is: events are not counted by the client, so
            # dropping one desynchronises nothing.
            if head[1] not in XKB_EVENT_ALLOW:
                return self.withhold("event:XKB%d" % head[1])
            return None

        if code in KEY_EVENT_CODES and not self._focus_is_ours():
            # The keyboard's delivery rule.  Normally a key event reaches this
            # client because the server sent it here -- the focus is one of its
            # windows -- and that is left alone.  A *grab* is the other way to
            # receive one: while it is held every keystroke in the session
            # arrives here whatever the user is typing into, which is the
            # keylogger this project exists to refuse.  Nothing in a KeyPress
            # distinguishes the two, so the question is asked of the server
            # instead: while the focus is somebody else's window, a key event
            # is not this client's to see.
            return self.withhold(
                "event:%s" % DROPPABLE_EVENT_NAMES.get(code, code))

        if code in POINTER_EVENT_CODES and len(head) >= 32:
            # Motion, button and crossing events carry the *global* pointer
            # position, and a client may grab the pointer on a window of its
            # own -- after which the server reports every one of them to the
            # grabbing client, wherever the pointer is.  Measured through the
            # proxy: with a grab held on a 40x30 window, the pointer moving
            # across the desktop reported (200,150), (700,500), (1100,800) --
            # the whole-screen trace the ninth pass bounded QueryPointer for,
            # the tenth refused crossing events on the root for, and the
            # twelfth closed the untracked-window default for, arriving by a
            # fourth road.
            #
            # The grab itself is left alone: menus track the pointer with one
            # and drag-and-drop cannot work without it.  What is bounded is the
            # *position*, by exactly the test bound_pointer_reply uses on a
            # reply -- the event's window-relative coordinates against the
            # window's tracked size.  Inside, the client is entitled to the
            # position (it could compute it from its own window's origin);
            # outside -- which is what a grab delivers -- it is somebody else's
            # business, so the root coordinates, the child window and the
            # modifier state go blank while the event itself is still
            # delivered, so the menu still sees the pointer move.
            return self._bound_event_position(head) if self.enforce else None

        if code == 28 and len(head) >= 12:       # PropertyNotify
            # EV-3.  The selection itself stays allowed, because a GTK client
            # has to select PropertyChangeMask on the *settings manager's*
            # window -- foreign -- to notice a theme change, and reading
            # _XSETTINGS_SETTINGS there is deliberately permitted.  What is
            # refused is the notification for a property the client may not
            # read: it would otherwise learn that WM_NAME changed on a window
            # whose title it cannot see, and when -- a timing channel on
            # another application's documents, with no polling equivalent
            # precisely because the read is refused.
            #
            # An event mask cannot name atoms, which is why this is done here
            # and not in judge(): the request carries no atom to gate on.
            window, atom = self.word(head, 4), self.word(head, 8)
            if self.is_foreign(window) \
                    and self.atom_name(atom) not in FOREIGN_PROPERTY_ALLOW:
                # A requestor mid-INCR transfer is the exception: the client
                # owns the selection, the requestor is somebody else's window,
                # and PropertyNotify on it is how the owner learns a chunk was
                # consumed.  Withholding that stalls a transfer the gate has
                # already approved.
                if not self.granted(self.selection_requestors, window):
                    return self.withhold("event:PropertyNotify")
                # ...and this event *is* the far side taking another chunk, so
                # it is also what keeps the grant alive for the rest of a
                # transfer longer than SELECTION_GRANT_SECONDS.  Only a
                # server-generated one counts: a forged PropertyNotify would
                # let the client renew its own grant, the EV-7 trick the
                # SelectionRequest arm above refuses for the same reason.
                if not head[0] & 0x80:
                    self.renew_selection_grant(window, atom)
            return None

        if code == 31 and len(head) >= 24:       # SelectionNotify
            # Match on (requestor, target): the property field comes back as
            # None on the refusal this patch exists to handle, so it cannot be
            # part of the key.  Restore the real selection atom;
            # the property stays None, which is exactly a clean "no owner".
            # No enforce guard here, unlike the rewrites above: this one undoes
            # a substitution the *request* path made, and that path registers
            # one only when enforcing, so under --dry-run there is nothing in
            # `gated` to match and the arm is inert on its own.
            requestor, target = self.word(head, 8), self.word(head, 16)
            with self.lock:
                selection = self.gated.pop((requestor, target), None)
            if selection is not None:
                patched = bytearray(head)
                struct.pack_into(self.endian + "I", patched, 12, selection)
                return bytes(patched)
        return None

    def patch_generic_event(self, head, body):
        """Default-deny for XGE: forward only a listed (extension, evtype),
        drop and log everything else.

        The relay cannot rewrite an XGE field by field -- its layout is the
        emitting extension's business, not the core protocol's -- so an XGE that
        carries something the policy would blank in a reply (an XInput2 crossing
        event's global position and modifiers, say) cannot be scrubbed on the
        way out; it can only be passed or withheld.  Passing every one made the
        request-side selection gate the sole defence.  This closes that: an XGE
        reaches the client only if GENERIC_EVENT_ALLOW lists it, and anything
        else is dropped -- safe, because events are not counted and dropping one
        desyncs nothing -- and named once in the log so the allowlist can be
        grown to exactly what real applications need.

        In dry-run nothing is enforced, so the event passes; the log still names
        it, which is the whole point of looking before enforcing.
        """
        if len(head) < 10:
            return None
        major = head[1]
        evtype = struct.unpack_from(self.endian + "H", head, 8)[0]
        name = self.extension_opcodes.get(major) \
            or self.profile.extension_name(major)
        allowed = GENERIC_EVENT_ALLOW.get(name)
        passed = allowed == "all" or (allowed is not None and evtype in allowed)
        self.note_generic_event(name, major, evtype, passed)
        if passed:
            return self._bound_xi_event(name, evtype, head, body)
        return self.DROP_EVENT if self.enforce else None

    #: XInput2 device events -- key, button, motion and crossing -- share one
    #: layout: the event window at 24 and the child at 28 in the header, then
    #: the root position at 32, the window-relative one at 40 (both FP1616,
    #: whose integer part is the high half) and the modifier set at 56.
    XI_DEVICE_EVENTS = frozenset({2, 3, 4, 5, 6, 7, 8})

    def _focus_is_ours(self):
        """True unless the server says another application holds the focus.

        A focus the proxy cannot ask about at all (no upstream connection)
        answers True: the rule is not meant to make a client deaf when the
        machinery is missing.  **None is not "ours"**, though, and that
        distinction was measured rather than reasoned: with `None` treated as
        ours, exactly one keystroke of a captured word slipped through, and
        instrumenting the decision showed why -- of twelve evaluations, ten saw
        the trusted window and two saw a focus of 0.  A window manager reports
        no focus for a moment while it moves one, and a key arriving in that
        moment is nobody's -- certainly not a client that only sees it because
        it holds a grab.  PointerRoot (1) stays "ours": there the keys belong
        to whatever the pointer is over, which is the case a bare server and a
        focus-follows-mouse desktop both use.

        Which window a manager focuses is its own business -- openbox and
        metacity focus the client's own window, measured in the ninth pass --
        so a manager that focuses a frame of its own would make this drop keys
        the client should have had, and the log would name it.
        """
        window = focus_window(self.endian)
        if window == 0:
            # The server says nobody holds the focus.  This has to be spelled
            # out: is_foreign() reads 0 as "None" and answers False for it
            # everywhere else, because 0 is how a request says "no window" --
            # so without this line "nobody is focused" read as "we are".
            ours = False
        elif window is None:
            # The focus could not be read at all: no anchor connection, or one
            # that has died under us.  Answering "ours" here -- which this did
            # unconditionally until the twenty-eighth pass -- hands every
            # keystroke to a client holding a keyboard grab, which is precisely
            # the keylogger the grab rule exists to stop, reinstated by the
            # failure of the machinery that stops it.
            #
            # Answering "not ours" unconditionally is not the fix either: with
            # no oracle *every* client goes deaf, including the one the user is
            # typing into, so a dead anchor would break the whole session.
            #
            # The way out is that the two cases are distinguishable. Without a
            # grab, X delivers a key event only to the focused window's chain,
            # so a client that is not focused is not being sent keys in the
            # first place and withholding costs it nothing; *with* a grab, the
            # server delivers every keystroke to it wherever the user is
            # typing, and that is the whole attack. So an unreadable focus is
            # "ours" only for a client that is not holding the keyboard.
            ours = not self.keyboard_grabbed
            if not ours:
                self.profile.note_focus_oracle_lost()
        else:
            ours = window == 1 or not self.is_foreign_window(window)
        return ours

    def _bound_xi_event(self, name, evtype, head, body):
        """The event-position bound, applied to an XInput2 device event.

        The tenth pass said a generic event cannot be scrubbed field by field
        because its layout belongs to the extension, and left the channel
        pass-or-drop.  That is true in general and false for the events that
        matter here: XI2's device events have one documented shape, which the
        pointer bound already relies on for XIQueryPointer's *reply*.  Without
        this, gating the core pointer grab and not this one would have been the
        same half-measure as gating the core keyboard grab alone: an XI2
        pointer grab reported the whole desktop -- (200,150), (700,500),
        (1100,800) -- through events the policy had admitted.
        """
        if name != "XInputExtension" or evtype not in self.XI_DEVICE_EVENTS:
            return None
        if evtype in (2, 3) and not self._focus_is_ours():
            # Named too, and for the same reason: this one is reached with the
            # evtype already logged as *allowed* by note_generic_event -- it is
            # in the XGE allowlist -- so without a line here the log positively
            # asserts that the events it is swallowing got through.
            return self.withhold(                # XI_KeyPress / XI_KeyRelease
                "event:XI_Key%s" % ("Press" if evtype == 2 else "Release"))
        if len(head) < 32 or len(body) < 40:
            return None
        window = self.word(head, 24)
        state = self.profile.window_state(window)
        event_x, event_y = struct.unpack_from(self.endian + "ii", body, 8)
        inside = bool(state) and state[3] \
            and 0 <= event_x >> 16 < state[0] and 0 <= event_y >> 16 < state[1]
        if inside:
            return None
        if not self.enforce:
            return None
        patched_head, patched_body = bytearray(head), bytearray(body)
        struct.pack_into(self.endian + "I", patched_head, 28, 0)   # child
        struct.pack_into(self.endian + "ii", patched_body, 0, 0, 0)  # root x, y
        for offset in range(24, 40, 4):                            # modifiers
            struct.pack_into(self.endian + "I", patched_body, offset, 0)
        return bytes(patched_head), bytes(patched_body)

    def note_dropped_event(self, label):
        """Log a withheld fixed event, once per kind on this connection.

        Twenty-sixth pass.  Withholding an event is the policy's most
        user-visible act -- it is what makes an application hang rather than
        report an error, because there is no reply for the server to turn into
        an X error -- and it was the one act the operation log did not record.
        The generic-event path beside this has named its drops since the tenth
        pass; the fixed-event path returned DROP_EVENT into a bare `continue`.
        So the run that first measured the INCR stall finished with the log
        saying, in as many words, that nothing was blocked, while the proxy was
        exactly what had stopped the transfer.  An operator reading that log
        would have no reason to suspect the filter.

        Same once-per-(operation, verdict) shape as sentinel() and
        note_generic_event, so a stream of withheld key events still costs one
        line and one set-membership test on the hot path.
        """
        seen_key = ("event", label)
        if seen_key in self.seen:
            return
        self.seen.add(seen_key)
        if self.profile.note_first_seen((label, False), self.describe(),
                                        self.peer_label(), False,
                                        "withheld event"):
            line = ("new operation: %-40s %-8s %s [%s]"
                    % (label, "blocked", self.describe(), self.peer_label()))
            if self.alert_new:
                print(line, file=sys.stderr)
            self.profile.log_line(line)

    def withhold(self, label):
        """Refuse an event: report it always, withhold it only when enforcing.

        Twenty-seventh pass.  `--dry-run` exists so an operator can watch an
        application and read off what enforcing would cost before paying it,
        and the XGE path says so in as many words -- "in dry-run nothing is
        enforced, so the event passes; the log still names it, which is the
        whole point of looking before enforcing".  The fixed-event path made
        only half of that promise: a blanket early return skipped the arms
        entirely, so a dry run neither withheld an event nor said it would.
        The drops the twenty-sixth pass had just made visible were visible only
        in the mode that also performed them, which is the mode where the
        application has already broken.

        So the decision is now always taken and always reported, and the enforce
        flag governs only whether the event is actually withheld -- the same
        shape the request path has always had, where judge() runs and the
        substitution is registered `if self.enforce`.
        """
        self.note_dropped_event(label)
        return self.DROP_EVENT if self.enforce else None

    def note_generic_event(self, name, major, evtype, passed):
        """Log a generic (XGE) event the first time this connection meets one,
        the same once-per-(operation, verdict) shape sentinel() uses for
        requests."""
        seen_key = ("xge", major, evtype, passed)
        if seen_key in self.seen:
            return
        self.seen.add(seen_key)
        label = "%s:XGE%d" % (name or "ext%d" % major, evtype)
        if self.profile.note_first_seen((label, passed), self.describe(),
                                        self.peer_label(), passed, "generic event"):
            line = ("new operation: %-40s %-8s %s [%s]"
                    % (label, "allowed" if passed else "blocked",
                       self.describe(), self.peer_label()))
            if self.alert_new:
                print(line, file=sys.stderr)
            self.profile.log_line(line)

    def handshake(self):
        if not super().handshake():
            return False
        try:
            self.find_root(self.setup_body)
        except (struct.error, IndexError):
            pass
        return True


def check_gtk():
    """Is the GTK binding installed?  Asked as soon as the arguments are
    parsed, so --gate ask on a machine without it fails immediately instead
    of after the proxy is already accepting clients.

    This deliberately stops at require_version.  Importing gi.repository.Gtk
    *initialises* GTK against whatever $DISPLAY says at the time, and at this
    point DISPLAY is still the caller's -- binding the prompt to the wrong
    display, permanently, because a later os.environ change cannot move it.
    require_version only checks the typelib is present, which is the half
    that can be answered this early.
    """
    try:
        import gi
        gi.require_version("Gtk", "3.0")
    except (ImportError, ValueError) as exc:
        raise SystemExit("--gate ask needs GTK (python3-gi and "
                         "gir1.2-gtk-3.0): %s" % exc)


def load_gtk():
    """Import GTK for real.  Only after $DISPLAY points at the desktop the
    prompt should appear on -- see check_gtk.

    GTK parses sys.argv as it initialises and would take our --display for
    its own, opening the proxy's display instead of the desktop's, so argv
    is hidden for the duration.
    """
    saved, sys.argv = sys.argv, sys.argv[:1]
    try:
        from gi.repository import Gtk, GLib
        return Gtk, GLib
    except (ImportError, ValueError) as exc:
        raise SystemExit("--gate ask needs GTK (python3-gi): %s" % exc)
    finally:
        sys.argv = saved


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--display",
                        help="display to offer clients (default: the first "
                             "free one from :20)")
    parser.add_argument("--ssh", metavar="HOST",
                        help="run ssh -X to HOST through the proxy; anything "
                             "after -- is the remote command")
    parser.add_argument("command", nargs=argparse.REMAINDER,
                        help="command to run through the proxy, after --")
    parser.add_argument("--upstream", default=os.environ.get("DISPLAY", ":0"),
                        help="the real display to forward to (default: $DISPLAY"
                             "); the prompt opens here too")
    parser.add_argument("--auth", metavar="FILE",
                        help="authority file (xauth format) for the cookie "
                             "clients must present to --display; created if "
                             "missing (default: a private temp file, removed "
                             "on exit)")
    parser.add_argument("--upstream-auth", metavar="FILE",
                        help="authority file holding the cookie for --upstream "
                             "(default: $XAUTHORITY, then ~/.Xauthority)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="report every connection and its outcome")
    parser.add_argument("--dry-run", action="store_true",
                        help="report what the policy would refuse, refusing "
                             "nothing; without it the policy is enforced")
    parser.add_argument("--enforce", action="store_true",
                        help=argparse.SUPPRESS)   # now the default, kept
                                                  # so old commands still run
    parser.add_argument("--gate", choices=("deny", "allow", "ask"),
                        default="deny",
                        help="what a filtered application may do with "
                             "CLIPBOARD or PRIMARY -- both reading one and "
                             "taking ownership of one, which is how it offers "
                             "a copy out: refuse (default), allow, or ask you, "
                             "showing the value and which application wants "
                             "it. 'deny' means copying out of the forwarded "
                             "application does not work either; 'ask' is the "
                             "setting that gives you both directions")
    parser.add_argument("--gate-timeout", type=int, default=20, metavar="S",
                        help="deny a pending prompt after this long (20)")
    parser.add_argument("--gate-remember", type=int, default=300, metavar="S",
                        help="how long 'Allow for a while' lasts (300)")
    parser.add_argument("--domain", metavar="NAME",
                        help="run as the filter for this trust domain: the "
                             "display and the cookie are derived from the "
                             "name, so nothing has to be remembered or passed "
                             "around. Runs in the foreground and lives until "
                             "it is stopped; if one is already running for "
                             "this name it says so and exits. Everything "
                             "behind one filter can read everything else "
                             "behind it, so the name is the security "
                             "boundary: one per account, or per application "
                             "you do not trust")
    parser.add_argument("--use", metavar="NAME",
                        help="run the command after -- against this domain's "
                             "filtered display; the environment is scoped to "
                             "that command and nothing else")
    parser.add_argument("--env", metavar="NAME",
                        help="print this domain's two export lines on stdout, "
                             "for eval in a shell script (everything else "
                             "goes to stderr, so the output is safe to eval)")
    parser.add_argument("--list", action="store_true",
                        help="list the filtered domains running for you")
    parser.add_argument("--stop", metavar="NAME",
                        help="stop the filter for a domain")
    parser.add_argument("--version", action="version",
                        version="xfilter %s" % __version__)
    parser.add_argument("--log", metavar="FILE",
                        help="also append the operation log (each new "
                             "operation, and the exit report) to FILE; it "
                             "always goes to stdout as well")
    args = parser.parse_args()
    args.enforce = not args.dry_run
    # The using side first: none of it starts a proxy, and none of it needs
    # the rest of the setup below.
    if args.list:
        return list_domains()
    if args.stop:
        return stop_domain(args.stop)
    if args.env:
        return print_domain_environment(args.env)
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if args.ssh:
        args.command = ["ssh", "-X", "-o", "ForwardX11Trusted=yes",
                        args.ssh] + args.command
    if args.use:
        if not args.command:
            raise SystemExit("--use %s needs a command: ... -- ssh -X %s"
                             % (args.use, args.use))
        return use_domain(args.use, args.command)

    if args.gate == "ask":
        check_gtk()
    if args.domain:
        # The starting side.  Idempotent on purpose: a login script or a unit
        # may run it every time, and the second run must be a no-op rather
        # than a second trust domain wearing the same name.
        running = domain_running(args.domain)
        if running:
            print("%s is already filtered on %s" % (args.domain, running))
            return
        args.display = args.display or domain_free_display(args.domain)
        args.auth = args.auth or domain_auth(args.domain)
    if args.display is None:
        args.display = free_display()
    minted_auth = not args.auth
    if minted_auth:
        # Every run gets a private cookie, spawned command or not: leaving the
        # display open to every local user would undo the point of the
        # exercise, and "you forgot --auth" is not a state worth offering.
        # Driving the proxy by hand is the same deal -- the two export lines
        # printed below carry the cookie to whatever shell wants it.
        handle, args.auth = tempfile.mkstemp(prefix="xfilter-display-")
        os.close(handle)
    Connection.verbose = args.verbose

    upstream_target = parse_display(args.upstream)
    upstream_auth, upstream_cookie = working_cookie(
        upstream_target,
        upstream_candidates(args.upstream_auth, args.upstream))
    expected = (cookie_for(args.auth, args.display, create=True)[1]
                if args.auth else None)

    # Every allowlisted extension has an inspector: fail loudly at startup if
    # EXTENSION_INSPECTORS names a method that does not exist, rather than
    # discovering it as a silent block when a client first uses the extension.
    _missing = [n for n, m in EXTENSION_INSPECTORS.items()
                if not callable(getattr(PolicyConnection, m, None))]
    if _missing:
        raise SystemExit("extension inspector method missing for: %s"
                         % ", ".join(sorted(_missing)))

    denied_opcodes = learn_denied_opcodes(upstream_target, upstream_cookie)
    extension_opcodes, extension_events = learn_extension_opcodes(
        upstream_target, upstream_cookie, ALLOWED_EXTENSIONS)
    policy_atoms = learn_atoms(upstream_target, upstream_cookie, POLICY_ATOMS)
    gated_ids = learn_selection_atoms(upstream_target, upstream_cookie,
                                      policy_atoms)
    profile = PolicyProfile()
    # Seed the profile with what the proxy learned for itself, so no rule
    # depends on a client having asked a question first: the atom names the
    # policy decides on, and the event base each extension was assigned (which
    # is how the event filter recognises, say, an XKB event).
    for name, atom in policy_atoms.items():
        profile.note_atom(atom, name)
    for opcode, name in extension_opcodes.items():
        profile.note_extension(opcode, name, extension_events.get(name))
    server, unix_path = listen(args.display)
    if args.domain:
        # Written only now: before listen() succeeded there was nothing to
        # point anybody at.  --list and --stop are its only readers; whether
        # the domain is *serving* is still settled by a handshake, never by
        # this file.
        with open(domain_pid_file(args.domain), "w") as handle:
            handle.write("%d\n%s\n" % (os.getpid(), args.domain))

    PolicyConnection.gate_mode = args.gate
    PolicyConnection.extension_opcodes = extension_opcodes
    PolicyConnection.gated_selection_ids = frozenset(gated_ids)
    if args.log:
        try:
            profile.log_file = open(args.log, "a", buffering=1)
        except OSError as exc:
            raise SystemExit("cannot open --log %s: %s" % (args.log, exc))
    if args.gate == "ask":
        PolicyConnection.gate = Gate(args.gate_timeout, args.gate_remember)

    def finish(signum=None, frame=None):
        profile.dump(enforcing=args.enforce)
        if profile.log_file is not None:
            profile.dump(stream=profile.log_file, enforcing=args.enforce)
        for path in (unix_path,
                     args.auth if minted_auth else None,
                     domain_pid_file(args.domain) if args.domain else None):
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass
        sys.stdout.flush()
        os._exit(0)

    signal.signal(signal.SIGINT, finish)
    signal.signal(signal.SIGTERM, finish)

    print("denied extensions hold opcodes: %s"
          % ", ".join("%s=%d" % (n, o) for o, n in sorted(
              denied_opcodes.items(), key=lambda kv: kv[1])) or "none",
          file=sys.stderr)
    print("argument-inspected extensions: %s"
          % (", ".join("%s=%d" % (n, o) for o, n in sorted(
              extension_opcodes.items(), key=lambda kv: kv[1])) or "none"),
          file=sys.stderr)
    print("gated selection atom ids: %s"
          % (", ".join(str(a) for a in sorted(gated_ids)) or "none"),
          file=sys.stderr)
    # Both of these are the same statement: the policy resolved the names it
    # decides on before any client connected, so no rule waits on a client to
    # ask a question it can simply not ask.
    print("policy atoms resolved: %d of %d; extension event bases learned: %s"
          % (len(policy_atoms), len(POLICY_ATOMS),
             ", ".join("%s=%d" % (n, e)
                       for n, e in sorted(extension_events.items())) or "none"),
          file=sys.stderr)
    if args.auth:
        print("\nrun clients with:\n"
              "    export XAUTHORITY=%s\n"
              "    export DISPLAY=%s\n"
              % (os.path.abspath(os.path.expanduser(args.auth)), args.display),
              file=sys.stderr)
    print("listening on %s, forwarding to %s (%s)"
          % (args.display, args.upstream,
             "enforcing" if args.enforce else "DRY RUN, nothing denied"),
          file=sys.stderr)
    if args.command:
        print("running: %s" % " ".join(args.command), file=sys.stderr)
        spawn(args.command, args.display,
              os.path.abspath(os.path.expanduser(args.auth)), finish)

    def serve():
        while True:
            client, _ = server.accept()
            PolicyConnection(client, upstream_target, upstream_cookie,
                             expected, profile, enforce=args.enforce,
                             denied_opcodes=denied_opcodes).start()

    # The accept loop always runs on its own thread, whatever the gate mode,
    # so the process has one shape instead of two.  The main thread then
    # waits for something that never finishes: under --gate ask that is GTK's
    # main loop, which insists on owning the main thread and is what pumps the
    # prompt queue; otherwise there is nothing to draw and it waits on the
    # accept loop itself.  Serving starts first either way, so a display that
    # is slow to answer cannot hold up accepting clients.
    accepting = threading.Thread(target=serve, name="accept", daemon=True)
    accepting.start()

    threading.Thread(target=watch_upstream, name="upstream", daemon=True,
                     args=(upstream_target, args.upstream, finish)).start()


    if args.gate == "ask":
        # The prompt must talk to the real display directly: routing it
        # through our own filtered display would put the dialog's own
        # clipboard reads back in front of the gate.  check_gtk() has already
        # confirmed the binding exists; this is where it is bound to a
        # display, which is why DISPLAY is set first.
        os.environ["DISPLAY"] = args.upstream
        os.environ["XAUTHORITY"] = upstream_auth
        Gtk, GLib = load_gtk()
        GLib.timeout_add(100, PolicyConnection.gate.pump)
        Gtk.main()
    else:
        accepting.join()

    # Neither wait returns while the proxy is healthy, so arriving here means
    # the loop stopped on its own rather than on a signal, which finish()
    # would have handled.
    print("the proxy stopped serving; exiting", file=sys.stderr)


if __name__ == "__main__":
    main()
