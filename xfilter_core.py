"""X protocol relay: the machinery xfilter.py is built on.

This is a library, not a command.  It holds the parts that have nothing to
do with policy -- the connection setup and cookie swap, the request and
reply parsing, atom and extension bookkeeping, and the profile that
counts what it sees.  ``xfilter.py`` imports all of it and adds the
decisions, so this file has to sit next to it.

It does also run on its own as a pure profiler, which is how the policy in
xfilter.py was derived in the first place: relay everything, deny nothing,
and read what the applications actually asked for.

    python3 xfilter_core.py --display :20 --auth ~/.Xauthority-filter --upstream :0
    XAUTHORITY=~/.Xauthority-filter DISPLAY=:20 ssh -X -o ForwardX11Trusted=yes host

Ctrl-C prints the profile.  In this mode nothing is ever denied.

How it works
------------
Each client connection is handled by two threads: one parses the
client->server direction into requests, one parses server->client into
replies, errors and events.  Both relay the exact bytes they read, so a
parsing mistake shows up as wrong statistics, never as a corrupted
session.

Three things are tracked beyond raw counts:

  * ``QueryExtension`` requests are paired with their replies by sequence
    number, which is how the proxy learns the major opcode each extension
    was assigned on this connection.  Extension requests are then reported
    by name rather than by number.

  * The setup reply carries ``resource-id-base`` and ``resource-id-mask``,
    the range of XIDs this client may create.  Any XID outside it belongs
    to somebody else, so requests naming one are flagged as touching a
    foreign resource -- those are exactly the requests a policy would have
    to rule on.

  * ``BIG-REQUESTS`` is tracked explicitly.  A request length of zero is
    illegal in the core protocol and only legal once the client has
    enabled that extension with ``BigReqEnable``; a zero length then means
    "read the real 32-bit length next".  The relay watches for the
    ``BigReqEnable`` request going past and only accepts the zero-length
    form afterwards -- a zero-length header from a client that never
    enabled it is unframeable (the server would reject it and resume
    parsing mid-body), so the connection is dropped rather than guessed
    at.  The extended length is also held to the server's advertised
    maximum, so a lie in that field cannot make the relay allocate
    gigabytes before the server would have refused it.

Requests whose length field lies are the one thing that can desynchronise
the parser.  A well-formed client never does it; a hostile one that tries
is dropped at the first unframeable header rather than being allowed to
smuggle bytes the parser cannot see.
"""

import argparse
import collections
import hmac
import os
import signal
import socket
import struct
import subprocess
import sys
import threading

CORE_NAMES = {
    1: "CreateWindow", 2: "ChangeWindowAttributes", 3: "GetWindowAttributes",
    4: "DestroyWindow", 5: "DestroySubwindows", 6: "ChangeSaveSet",
    7: "ReparentWindow", 8: "MapWindow", 9: "MapSubwindows",
    10: "UnmapWindow", 11: "UnmapSubwindows", 12: "ConfigureWindow",
    13: "CirculateWindow", 14: "GetGeometry", 15: "QueryTree",
    16: "InternAtom", 17: "GetAtomName", 18: "ChangeProperty",
    19: "DeleteProperty", 20: "GetProperty", 21: "ListProperties",
    22: "SetSelectionOwner", 23: "GetSelectionOwner", 24: "ConvertSelection",
    25: "SendEvent", 26: "GrabPointer", 27: "UngrabPointer",
    28: "GrabButton", 29: "UngrabButton", 30: "ChangeActivePointerGrab",
    31: "GrabKeyboard", 32: "UngrabKeyboard", 33: "GrabKey", 34: "UngrabKey",
    35: "AllowEvents", 36: "GrabServer", 37: "UngrabServer",
    38: "QueryPointer", 39: "GetMotionEvents", 40: "TranslateCoordinates",
    41: "WarpPointer", 42: "SetInputFocus", 43: "GetInputFocus",
    44: "QueryKeymap", 45: "OpenFont", 46: "CloseFont", 47: "QueryFont",
    48: "QueryTextExtents", 49: "ListFonts", 50: "ListFontsWithInfo",
    51: "SetFontPath", 52: "GetFontPath", 53: "CreatePixmap",
    54: "FreePixmap", 55: "CreateGC", 56: "ChangeGC", 57: "CopyGC",
    58: "SetDashes", 59: "SetClipRectangles", 60: "FreeGC", 61: "ClearArea",
    62: "CopyArea", 63: "CopyPlane", 64: "PolyPoint", 65: "PolyLine",
    66: "PolySegment", 67: "PolyRectangle", 68: "PolyArc", 69: "FillPoly",
    70: "PolyFillRectangle", 71: "PolyFillArc", 72: "PutImage",
    73: "GetImage", 74: "PolyText8", 75: "PolyText16", 76: "ImageText8",
    77: "ImageText16", 78: "CreateColormap", 79: "FreeColormap",
    80: "CopyColormapAndFree", 81: "InstallColormap", 82: "UninstallColormap",
    83: "ListInstalledColormaps", 84: "AllocColor", 85: "AllocNamedColor",
    86: "AllocColorCells", 87: "AllocColorPlanes", 88: "FreeColors",
    89: "StoreColors", 90: "StoreNamedColor", 91: "QueryColors",
    92: "LookupColor", 93: "CreateCursor", 94: "CreateGlyphCursor",
    95: "FreeCursor", 96: "RecolorCursor", 97: "QueryBestSize",
    98: "QueryExtension", 99: "ListExtensions", 100: "ChangeKeyboardMapping",
    101: "GetKeyboardMapping", 102: "ChangeKeyboardControl",
    103: "GetKeyboardControl", 104: "Bell", 105: "ChangePointerControl",
    106: "GetPointerControl", 107: "SetScreenSaver", 108: "GetScreenSaver",
    109: "ChangeHosts", 110: "ListHosts", 111: "SetAccessControl",
    112: "SetCloseDownMode", 113: "KillClient", 114: "RotateProperties",
    115: "ForceScreenSaver", 116: "SetPointerMapping", 117: "GetPointerMapping",
    118: "SetModifierMapping", 119: "GetModifierMapping", 127: "NoOperation",
}

# Core requests that name a resource somebody else may own, and where that
# XID sits in the request body (offset past the 4-byte header).  Only the
# requests a policy would care about are listed; drawing requests name the
# client's own drawables and are uninteresting here.
RESOURCE_FIELDS = {
    2: [("window", 0)], 3: [("window", 0)], 14: [("drawable", 0)],
    15: [("window", 0)], 18: [("window", 0)], 19: [("window", 0)],
    20: [("window", 0)], 21: [("window", 0)], 22: [("owner", 0)],
    24: [("requestor", 0)], 25: [("destination", 0)],
    26: [("grab-window", 0)], 28: [("grab-window", 0)],
    31: [("grab-window", 0)], 33: [("grab-window", 0)],
    42: [("focus", 0)], 61: [("window", 0)],
    62: [("src", 0), ("dst", 4)], 63: [("src", 0), ("dst", 4)],
    72: [("drawable", 0)], 73: [("drawable", 0)], 114: [("window", 0)],
}

# Destinations of SendEvent that are not XIDs at all.
SENDEVENT_SPECIAL = {0, 1}

# Requests whose interesting argument is an atom rather than a resource:
# which selection, which property.  This is what a policy keys on --
# ConvertSelection(CLIPBOARD) and ConvertSelection(_XSETTINGS_S0) are the
# same request and want opposite answers.
ATOM_FIELDS = {
    18: 4,      # ChangeProperty     -> property
    19: 4,      # DeleteProperty     -> property
    20: 4,      # GetProperty        -> property
    22: 4,      # SetSelectionOwner  -> selection
    23: 0,      # GetSelectionOwner  -> selection
    24: 4,      # ConvertSelection   -> selection
}

# Minor opcodes for the extensions worth reading at a glance.  Add more
# from xcb-proto as the policy grows to cover them; anything missing is
# reported by number.
EXT_REQUESTS = {
    "RENDER": {
        0: "QueryVersion", 1: "QueryPictFormats", 2: "QueryPictIndexValues",
        4: "CreatePicture", 5: "ChangePicture",
        6: "SetPictureClipRectangles", 7: "FreePicture", 8: "Composite",
        10: "Trapezoids", 11: "Triangles", 12: "TriStrip", 13: "TriFan",
        17: "CreateGlyphSet", 18: "ReferenceGlyphSet", 19: "FreeGlyphSet",
        20: "AddGlyphs", 22: "FreeGlyphs", 23: "CompositeGlyphs8",
        24: "CompositeGlyphs16", 25: "CompositeGlyphs32",
        26: "FillRectangles", 27: "CreateCursor", 28: "SetPictureTransform",
        29: "QueryFilters", 30: "SetPictureFilter", 31: "CreateAnimCursor",
        32: "AddTraps", 33: "CreateSolidFill", 34: "CreateLinearGradient",
        35: "CreateRadialGradient", 36: "CreateConicalGradient",
    },
    "XFIXES": {
        0: "QueryVersion", 1: "ChangeSaveSet", 2: "SelectSelectionInput",
        3: "SelectCursorInput", 4: "GetCursorImage", 5: "CreateRegion",
        10: "DestroyRegion", 11: "SetRegion", 12: "CopyRegion",
        13: "UnionRegion", 14: "IntersectRegion", 15: "SubtractRegion",
        16: "InvertRegion", 17: "TranslateRegion", 18: "RegionExtents",
        19: "FetchRegion", 20: "SetGCClipRegion", 21: "SetWindowShapeRegion",
        22: "SetPictureClipRegion", 23: "SetCursorName", 24: "GetCursorName",
        25: "GetCursorImageAndName", 26: "ChangeCursor",
        27: "ChangeCursorByName", 29: "HideCursor", 30: "ShowCursor",
    },
    "XKEYBOARD": {
        0: "UseExtension", 1: "SelectEvents", 3: "Bell", 4: "GetState",
        5: "LatchLockState", 6: "GetControls", 7: "SetControls",
        8: "GetMap", 9: "SetMap", 10: "GetCompatMap", 11: "SetCompatMap",
        12: "GetIndicatorState", 13: "GetIndicatorMap",
        14: "SetIndicatorMap", 15: "GetNamedIndicator",
        16: "SetNamedIndicator", 17: "GetNames", 18: "SetNames",
        19: "GetGeometry", 20: "SetGeometry", 21: "PerClientFlags",
        22: "ListComponents", 23: "GetKbdByName", 24: "GetDeviceInfo",
        25: "SetDeviceInfo", 101: "SetDebuggingFlags",
    },
    "RANDR": {
        0: "QueryVersion", 2: "SetScreenConfig", 4: "SelectInput",
        5: "GetScreenInfo", 6: "GetScreenSizeRange", 7: "SetScreenSize",
        8: "GetScreenResources", 9: "GetOutputInfo",
        10: "ListOutputProperties", 11: "QueryOutputProperty",
        12: "ConfigureOutputProperty", 13: "ChangeOutputProperty",
        14: "DeleteOutputProperty", 15: "GetOutputProperty",
        16: "CreateMode", 17: "DestroyMode", 18: "AddOutputMode",
        19: "DeleteOutputMode", 20: "GetCrtcInfo", 21: "SetCrtcConfig",
        22: "GetCrtcGammaSize", 23: "GetCrtcGamma", 24: "SetCrtcGamma",
        25: "GetScreenResourcesCurrent", 26: "SetCrtcTransform",
        27: "GetCrtcTransform", 28: "GetPanning", 29: "SetPanning",
        30: "SetOutputPrimary", 31: "GetOutputPrimary", 32: "GetProviders",
        33: "GetProviderInfo", 34: "SetProviderOffloadSink",
        35: "SetProviderOutputSource", 36: "ListProviderProperties",
        37: "QueryProviderProperty", 38: "ConfigureProviderProperty",
        39: "ChangeProviderProperty", 40: "DeleteProviderProperty",
        41: "GetProviderProperty", 42: "GetMonitors", 43: "SetMonitor",
        44: "DeleteMonitor", 45: "CreateLease", 46: "FreeLease",
    },
    "SHAPE": {
        0: "QueryVersion", 1: "Rectangles", 2: "Mask", 3: "Combine",
        4: "Offset", 5: "QueryExtents", 6: "SelectInput",
        7: "InputSelected", 8: "GetRectangles",
    },
    "MIT-SHM": {
        0: "QueryVersion", 1: "Attach", 2: "Detach", 3: "PutImage",
        4: "GetImage", 5: "CreatePixmap", 6: "AttachFd", 7: "CreateSegment",
    },
}

# Atoms 1..68 exist without ever being interned, so no InternAtom reply
# will ever name them (X11/Xatom.h).
PREDEFINED_ATOMS = {
    1: "PRIMARY", 2: "SECONDARY", 3: "ARC", 4: "ATOM", 5: "BITMAP",
    6: "CARDINAL", 7: "COLORMAP", 8: "CURSOR", 9: "CUT_BUFFER0",
    10: "CUT_BUFFER1", 11: "CUT_BUFFER2", 12: "CUT_BUFFER3",
    13: "CUT_BUFFER4", 14: "CUT_BUFFER5", 15: "CUT_BUFFER6",
    16: "CUT_BUFFER7", 17: "DRAWABLE", 18: "FONT", 19: "INTEGER",
    20: "PIXMAP", 21: "POINT", 22: "RECTANGLE", 23: "RESOURCE_MANAGER",
    24: "RGB_COLOR_MAP", 25: "RGB_BEST_MAP", 26: "RGB_BLUE_MAP",
    27: "RGB_DEFAULT_MAP", 28: "RGB_GRAY_MAP", 29: "RGB_GREEN_MAP",
    30: "RGB_RED_MAP", 31: "STRING", 32: "VISUALID", 33: "WINDOW",
    34: "WM_COMMAND", 35: "WM_HINTS", 36: "WM_CLIENT_MACHINE",
    37: "WM_ICON_NAME", 38: "WM_ICON_SIZE", 39: "WM_NAME",
    40: "WM_NORMAL_HINTS", 41: "WM_SIZE_HINTS", 42: "WM_ZOOM_HINTS",
    43: "MIN_SPACE", 44: "NORM_SPACE", 45: "MAX_SPACE", 46: "END_SPACE",
    47: "SUPERSCRIPT_X", 48: "SUPERSCRIPT_Y", 49: "SUBSCRIPT_X",
    50: "SUBSCRIPT_Y", 51: "UNDERLINE_POSITION", 52: "UNDERLINE_THICKNESS",
    53: "STRIKEOUT_ASCENT", 54: "STRIKEOUT_DESCENT", 55: "ITALIC_ANGLE",
    56: "X_HEIGHT", 57: "QUAD_WIDTH", 58: "WEIGHT", 59: "POINT_SIZE",
    60: "RESOLUTION", 61: "COPYRIGHT", 62: "NOTICE", 63: "FONT_NAME",
    64: "FAMILY_NAME", 65: "FULL_NAME", 66: "CAP_HEIGHT", 67: "WM_CLASS",
    68: "WM_TRANSIENT_FOR",
}


class Profile:
    """Thread-safe request counters shared by every connection."""

    def __init__(self):
        self.lock = threading.Lock()
        self.requests = collections.Counter()
        self.foreign = collections.Counter()
        self.foreign_example = {}
        self.extensions = {}          # major opcode -> extension name
        self.extension_events = {}    # extension name -> first_event base
        self.missing_extensions = set()
        self.atoms = dict(PREDEFINED_ATOMS)   # atom id -> name, server-wide
        self.ranges = []              # (base, mask) of every connection
        self.connections = 0

    def note_extension(self, opcode, name, first_event=None):
        with self.lock:
            self.extensions[opcode] = name
            if first_event:
                # first_event == 0 means the extension defines no events; only
                # a non-zero base names a range we could recognise an event in.
                self.extension_events[name] = first_event

    def extension_name(self, opcode):
        with self.lock:
            return self.extensions.get(opcode)

    def event_base(self, name):
        """The first_event an extension was assigned, or None if it has no
        events or has not been seen.  patch_event uses this to recognise an
        extension's events by their type byte, the way judge() recognises its
        requests by major opcode."""
        with self.lock:
            return self.extension_events.get(name)

    def note_range(self, base, mask):
        with self.lock:
            self.ranges.append((base, mask))

    def is_foreign(self, xid):
        """True if no connection we proxy could have created this XID.

        Applications open several connections -- an IDE may open nine --
        and each gets its own resource-id range, so a per-connection test
        would flag an application's own windows as somebody else's.  A
        sibling connecting later than the request that names its resources
        is possible in principle and would misreport that one request.
        """
        if xid == 0:
            return False
        with self.lock:
            for base, mask in self.ranges:
                if (xid & ~mask) == base:
                    return False
        return True

    def note_atom(self, atom, name):
        with self.lock:
            self.atoms[atom] = name

    def note_missing_extension(self, name):
        with self.lock:
            self.missing_extensions.add(name)

    def note_request(self, key, atom=None, foreign_field=None,
                     foreign_xid=None):
        # Atoms are resolved at dump time, not here: the InternAtom reply
        # naming an atom can arrive after a request that already used it.
        entry = (key, atom)
        with self.lock:
            self.requests[entry] += 1
            if foreign_field is not None:
                self.foreign[entry] += 1
                self.foreign_example.setdefault(
                    entry, "%s=0x%x" % (foreign_field, foreign_xid))

    def note_connection(self):
        with self.lock:
            self.connections += 1

    def dump(self, stream=sys.stdout):
        with self.lock:
            requests = self.requests.most_common()
            foreign = dict(self.foreign)
            example = dict(self.foreign_example)
            extensions = dict(self.extensions)
            missing = sorted(self.missing_extensions)
            atoms = dict(self.atoms)
            connections = self.connections

        def render(entry):
            key, atom = entry
            if atom is None:
                return key
            name = atoms.get(atom)
            # The atom's name came from the client that interned it.
            return "%s(%s)" % (key, printable(name) if name is not None
                               else "atom 0x%x" % atom)

        total = sum(c for _, c in requests)
        print("\n%d connections, %d requests\n" % (connections, total),
              file=stream)
        if extensions:
            print("extensions in use (major opcode assigned by the server):",
                  file=stream)
            for opcode, name in sorted(extensions.items()):
                print("    %-24s %d" % (name, opcode), file=stream)
            print(file=stream)
        if missing:
            # These names are whatever the client asked QueryExtension about.
            print("extensions asked for but not present: %s\n"
                  % ", ".join(printable(name) for name in missing), file=stream)

        print("%8s  %-46s %8s  %s"
              % ("count", "request", "foreign", "example"), file=stream)
        for entry, count in requests:
            n = foreign.get(entry, 0)
            print("%8d  %-46s %8s  %s"
                  % (count, render(entry), n or "", example.get(entry, "")),
                  file=stream)
        stream.flush()


def read_exactly(sock, n):
    """Read exactly n bytes, or return None once the peer closes."""
    chunks = []
    while n:
        data = sock.recv(n)
        if not data:
            return None
        chunks.append(data)
        n -= len(data)
    return b"".join(chunks)


def pad4(n):
    return (4 - n % 4) % 4


#: How much of a client-supplied name is worth printing.  A WM_CLASS is a word
#: or two; anything past this is padding meant to push the real line off the
#: screen.
LABEL_LIMIT = 64


def printable(value, limit=LABEL_LIMIT):
    """Clean a string the *client* chose, for printing, logging or a dialog.

    Everything the proxy says about a client can quote something the client
    named itself: WM_CLASS, an atom, an extension it asked for.  Those strings
    land in three places that matter -- the operator's terminal, where an
    escape sequence is not text but an instruction; the --log file, where a
    newline forges a whole line of evidence; and the gate prompt, which is the
    one moment the user is deciding something.  Measured before this existed: a
    client that called itself "xterm\\nnew operation: core:GetImage  allowed
    trusted desktop app [local pid 1, uid 0]" put exactly that line in the log
    and on the terminal, three times, indistinguishable from a real one.

    Cleaning happens on the way *out*, never on the way in: the policy matches
    on the bytes the client actually sent, and a name sanitised before it is
    matched is a way to make one name pass as another.
    """
    text = str(value)
    cleaned = "".join(ch if ch.isprintable() else "?" for ch in text)
    return cleaned if len(cleaned) <= limit else cleaned[:limit] + "..."


def parse_display(spec):
    """':20' -> unix socket path;  'host:20' -> (host, 6020)."""
    host, _, number = spec.rpartition(":")
    number = int(number.split(".")[0])
    if not host or host == "unix":
        return ("unix", "/tmp/.X11-unix/X%d" % number)
    if host == "localhost":
        host = "127.0.0.1"
    return ("tcp", (host, 6000 + number))


def connect_upstream(target):
    kind, address = target
    if kind == "unix":
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.connect(address)
    return sock


def cookies_for(xauthority, display, create=False):
    """Pull the MIT-MAGIC-COOKIE-1 for a display out of an xauth file.

    With create=True a missing entry is generated rather than fatal, which
    is what the proxy does for its own display: getting that file right by
    hand is the single fiddliest part of running this thing.
    """
    number = display.rpartition(":")[2].split(".")[0]
    env = dict(os.environ)
    path = os.path.expanduser(xauthority) if xauthority else None
    if path:
        env["XAUTHORITY"] = path

    def entries():
        try:
            return subprocess.run(["xauth", "list"], env=env, check=False,
                                  capture_output=True, text=True).stdout
        except FileNotFoundError as exc:
            raise SystemExit("xauth is not installed: %s" % exc)

    def find(out):
        """Every cookie for this display, in file order.

        A display often has more than one entry -- one per address family,
        or a stale one left by an earlier session -- and they need not
        share a value.  Callers that can test a cookie should try them
        all rather than trust the first.
        """
        found = []
        for line in out.splitlines():
            fields = line.split()
            if len(fields) == 3 and fields[1] == "MIT-MAGIC-COOKIE-1" \
                    and fields[0].rpartition(":")[2] == number:
                found.append((b"MIT-MAGIC-COOKIE-1",
                              bytes.fromhex(fields[2])))
        return found or None

    found = find(entries())
    if found:
        return found

    if create and path:
        if not os.path.exists(path):
            open(path, "ab").close()
            os.chmod(path, 0o600)
        subprocess.run(["xauth", "-f", path, "add", ":" + number,
                        "MIT-MAGIC-COOKIE-1", os.urandom(16).hex()],
                       env=env, check=False, capture_output=True)
        found = find(entries())
        if found:
            print("created a cookie for :%s in %s" % (number, path),
                  file=sys.stderr)
            return found

    raise SystemExit("no MIT-MAGIC-COOKIE-1 for display :%s in %s"
                     % (number, path or "~/.Xauthority"))


def cookie_for(xauthority, display, create=False):
    """The first cookie for a display; see cookies_for for the rest."""
    return cookies_for(xauthority, display, create)[0]


def upstream_candidates(upstream_auth, display):
    """Every cookie that might authenticate us to the real X server.

    Deliberately wider than one file.  The shell that starts the proxy has
    usually just been told to export XAUTHORITY for *clients* of the
    proxy, and that file has no entry for the upstream display -- so the
    plain ~/.Xauthority is checked too rather than failing outright.
    """
    paths = [upstream_auth] if upstream_auth else []
    if not upstream_auth:
        if os.environ.get("XAUTHORITY"):
            paths.append(os.environ["XAUTHORITY"])
        paths.append(os.path.expanduser("~/.Xauthority"))

    seen, candidates = set(), []
    for path in paths:
        try:
            cookies = cookies_for(path, display)
        except SystemExit:
            continue
        for cookie in cookies:
            if cookie[1] not in seen:
                seen.add(cookie[1])
                candidates.append((path, cookie))
    return candidates


def accepted_by_upstream(target, cookie):
    """Does the real X server accept this cookie?"""
    endian = "<" if sys.byteorder == "little" else ">"
    order = b"l" if sys.byteorder == "little" else b"B"
    name, data = cookie
    try:
        sock = connect_upstream(target)
    except OSError as exc:
        raise SystemExit("cannot reach the upstream display: %s" % exc)
    try:
        sock.sendall(struct.pack(endian + "cxHHHH2x", order, 11, 0,
                                 len(name), len(data))
                     + name + b"\0" * pad4(len(name))
                     + data + b"\0" * pad4(len(data)))
        head = read_exactly(sock, 8)
        return bool(head) and head[0] == 1
    finally:
        sock.close()


def working_cookie(target, candidates):
    """Pick the cookie the upstream server accepts, and say where it lives.

    The path matters to callers that need to run a helper against the same
    display -- a GUI, or xclip fetching a selection -- which can then use
    the very file that was just proven to work.
    """
    for path, cookie in candidates:
        if accepted_by_upstream(target, cookie):
            print("authenticated to the upstream display with the cookie "
                  "in %s" % path, file=sys.stderr)
            return path, cookie
    tried = ", ".join(sorted({path for path, _ in candidates})) or "no files"
    raise SystemExit(
        "the upstream X server refused every cookie found (%s).\n"
        "Check that --upstream names your real display and that xauth has "
        "a current cookie for it: xauth list" % tried)


class Connection(threading.Thread):
    """One client connection: handshake, then relay and parse both ways."""

    verbose = False

    def __init__(self, client, upstream_target, upstream_cookie,
                 expected_cookie, profile):
        super().__init__(daemon=True)
        self.client = client
        self.upstream_target = upstream_target
        self.upstream_cookie = upstream_cookie
        self.expected_cookie = expected_cookie
        self.profile = profile
        self.server = None
        self.endian = "<"
        self.sequence = 0
        self.id_base = 0
        self.id_mask = 0
        self.pending = {}             # sequence -> reply we want to read
        self.lock = threading.Lock()
        # BIG-REQUESTS state.  bigreq_opcode is the major opcode the server
        # assigned the extension on this connection (learned from the
        # client's own QueryExtension reply); big_requests_enabled turns
        # true only once BigReqEnable has gone past, which is the one thing
        # that makes a zero-length request legal.  max_request_units caps
        # how large a request we will frame -- the server's advertised
        # limit, raised by the BigReqEnable reply.
        self.bigreq_opcode = None
        self.big_requests_enabled = False
        self.max_request_units = 0
        # Credentials of the connecting process, for a local (unix) client:
        # unforgeable, unlike anything the client says about itself.
        self.peer_pid = self.peer_uid = self.peer_gid = None

    # -- handshake ---------------------------------------------------------

    def reject(self, reason):
        reason = reason.encode()
        body = reason + b"\0" * pad4(len(reason))
        self.client.sendall(struct.pack(self.endian + "BBHHH", 0, len(reason),
                                        11, 0, len(body) // 4) + body)

    def read_peer_credentials(self):
        """pid/uid/gid of a local client, or leave them None for a remote one."""
        try:
            creds = self.client.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED,
                struct.calcsize("3i"))
            self.peer_pid, self.peer_uid, self.peer_gid = struct.unpack(
                "3i", creds)
        except (OSError, AttributeError):
            pass

    def handshake(self):
        self.read_peer_credentials()
        head = read_exactly(self.client, 12)
        if not head:
            return False
        order = head[0:1]
        self.endian = "<" if order == b"l" else ">"
        _, major, minor, name_len, data_len = struct.unpack(
            self.endian + "cxHHHH2x", head)
        rest = read_exactly(self.client,
                            name_len + pad4(name_len) + data_len + pad4(data_len))
        if rest is None:
            return False
        data = rest[name_len + pad4(name_len):][:data_len]

        if self.expected_cookie and not hmac.compare_digest(
                data, self.expected_cookie):
            print("rejected a connection: client presented %s, expected the "
                  "cookie in --auth (is XAUTHORITY pointing at it?)"
                  % ("no auth data" if not data else "a different cookie"),
                  file=sys.stderr)
            self.reject("Invalid MIT-MAGIC-COOKIE-1 key")
            return False

        if self.verbose:
            print("client connected, presented %s"
                  % ("no auth data" if not data
                     else "cookie %s..." % data[:4].hex()), file=sys.stderr)
        self.server = connect_upstream(self.upstream_target)
        auth_name, auth_data = self.upstream_cookie
        setup = struct.pack(self.endian + "cxHHHH2x", order, major, minor,
                            len(auth_name), len(auth_data))
        setup += auth_name + b"\0" * pad4(len(auth_name))
        setup += auth_data + b"\0" * pad4(len(auth_data))
        self.server.sendall(setup)

        head = read_exactly(self.server, 8)
        if not head:
            return False
        status = head[0]
        extra = struct.unpack(self.endian + "H", head[6:8])[0] * 4
        body = read_exactly(self.server, extra) or b""
        self.client.sendall(head + body)
        if status != 1:
            print("the upstream display refused our connection setup; "
                  "the client will report a cookie error that is ours, "
                  "not its own", file=sys.stderr)
            return False
        if self.verbose:
            print("connection established through to the upstream display",
                  file=sys.stderr)
        self.id_base, self.id_mask = struct.unpack(
            self.endian + "II", body[4:12])
        self.max_request_units = struct.unpack_from(
            self.endian + "H", body, 18)[0] or 65535
        self.setup_body = body
        self.profile.note_range(self.id_base, self.id_mask)
        return True

    # -- parsing -----------------------------------------------------------

    def is_foreign(self, xid):
        """True if no connection we proxy could have created this XID.

        The overwhelmingly common case is a client naming a resource of its
        own, and that is two integer operations against this connection's own
        id range -- no lock taken, no scan of the application's other
        connections.  Only an id from outside this connection pays for the
        full check.  That is what makes gating every drawing request
        affordable rather than a per-PolyLine lock.
        """
        if xid & ~self.id_mask == self.id_base:
            return False
        return self.profile.is_foreign(xid)

    def request_key(self, opcode, minor):
        if opcode < 128:
            return "core:%s" % CORE_NAMES.get(opcode, opcode)
        name = self.profile.extension_name(opcode)
        if name is None:
            return "ext%d:%d" % (opcode, minor)
        return "%s:%s" % (name, EXT_REQUESTS.get(name, {}).get(minor, minor))

    def inspect(self, opcode, minor, body):
        key = self.request_key(opcode, minor)

        field = xid = None
        for name, offset in RESOURCE_FIELDS.get(opcode, ()):
            if len(body) < offset + 4:
                continue
            value = struct.unpack_from(self.endian + "I", body, offset)[0]
            if opcode == 25 and value in SENDEVENT_SPECIAL:
                continue
            if self.is_foreign(value):
                field, xid = name, value
                break

        atom = None
        offset = ATOM_FIELDS.get(opcode)
        if offset is not None and len(body) >= offset + 4:
            atom = struct.unpack_from(self.endian + "I", body, offset)[0]

        self.profile.note_request(key, atom, field, xid)
        self.learn(opcode, minor, body)

    def learn(self, opcode, minor, body):
        """Pair a naming request with its reply, so numbers get names later.

        This is the bookkeeping the parser needs regardless of statistics:
        which major opcode an extension was assigned, and the name behind an
        atom.  The enforcing proxy runs only this, not the counting in
        inspect(), because it keeps no per-request statistics of its own.
        """
        if opcode == 98 and len(body) >= 4:          # QueryExtension
            length = struct.unpack_from(self.endian + "H", body, 0)[0]
            name = body[4:4 + length].decode("latin-1")
            with self.lock:
                self.pending[self.sequence] = ("extension", name)
        elif opcode == 16 and len(body) >= 4:        # InternAtom
            length = struct.unpack_from(self.endian + "H", body, 0)[0]
            name = body[4:4 + length].decode("latin-1")
            with self.lock:
                self.pending[self.sequence] = ("intern", name)
        elif opcode == 17 and len(body) >= 4:        # GetAtomName
            value = struct.unpack_from(self.endian + "I", body, 0)[0]
            with self.lock:
                self.pending[self.sequence] = ("atomname", value)

    def resolve(self, pending, head, body):
        """Read a reply we asked to be told about: names for numbers."""
        kind, value = pending
        if kind == "extension":
            present, opcode, first_event = head[8], head[9], head[10]
            if present:
                self.profile.note_extension(opcode, value, first_event)
                if value == "BIG-REQUESTS":
                    self.bigreq_opcode = opcode
            else:
                self.profile.note_missing_extension(value)
        elif kind == "bigreq":
            # BigReqEnable reply carries the new, larger maximum request
            # length as a 32-bit count of 4-byte units.
            new_units = struct.unpack(self.endian + "I", head[8:12])[0]
            if new_units:
                self.max_request_units = new_units
        elif kind == "intern":
            atom = struct.unpack(self.endian + "I", head[8:12])[0]
            if atom:
                self.profile.note_atom(atom, value)
        elif kind == "atomname":
            length = struct.unpack(self.endian + "H", head[8:10])[0]
            self.profile.note_atom(value, body[:length].decode("latin-1"))

    def drop(self, reason):
        """Close a connection we cannot go on parsing safely."""
        print("closing a connection: %s" % reason, file=sys.stderr)

    def client_to_server(self):
        while True:
            head = read_exactly(self.client, 4)
            if head is None:
                break
            opcode, minor, length = struct.unpack(self.endian + "BBH", head)
            if length == 0:                          # claims BIG-REQUESTS form
                if not self.big_requests_enabled:
                    # Illegal without BigReqEnable: the server would answer
                    # BadLength and resume parsing four bytes in, mid-body,
                    # so any bytes that follow would reach it unclassified.
                    # There is no safe frame to read here -- drop the link.
                    self.drop("zero-length request before BigReqEnable "
                              "(possible request smuggling)")
                    break
                extra = read_exactly(self.client, 4)
                if extra is None:
                    break
                head += extra
                total_units = struct.unpack(self.endian + "I", extra)[0]
                if total_units < 2 or total_units > self.max_request_units:
                    self.drop("big request of %d units past the %d-unit "
                              "maximum"
                              % (total_units, self.max_request_units))
                    break
                total = total_units * 4
                body = read_exactly(self.client, total - 8) if total > 8 else b""
            else:
                if length > self.max_request_units:
                    self.drop("request of %d units past the %d-unit maximum"
                              % (length, self.max_request_units))
                    break
                body = read_exactly(self.client, length * 4 - 4) \
                    if length > 1 else b""
            if body is None:
                break
            self.sequence = (self.sequence + 1) & 0xFFFF
            # BigReqEnable makes the zero-length form legal from here on.  It
            # is recognised in this same thread that reads the next request,
            # so there is no window where a following big request races the
            # flag.  The reply (handled in the other thread) raises the size
            # ceiling; the client cannot send a bigger request before it has
            # that reply in hand anyway.
            if opcode == self.bigreq_opcode and minor == 0:
                self.big_requests_enabled = True
                with self.lock:
                    self.pending.setdefault(self.sequence, ("bigreq", None))
            try:
                self.inspect(opcode, minor, body)
            except (struct.error, IndexError, UnicodeDecodeError):
                pass                                 # never let stats break the relay
            self.forward(opcode, minor, head, body)

    def forward(self, opcode, minor, head, body):
        """Hand a request upstream.  Subclasses may rewrite or replace it."""
        self.server.sendall(head + body)

    def substitution(self, sequence, head, body):
        """Reply to send instead of the server's, or None to pass it on."""
        return None

    def discard_sequence(self, sequence):
        """A request failed: the server sent an error, and no reply follows.

        Whatever was being held for that reply will never be claimed, so
        subclasses drop it here.  Without this the tables that carry a
        substitution to its reply grow for the life of the connection -- a
        client that asks, in a loop, for something certain to fail (a pointer
        query naming a window it has just destroyed) makes the proxy the leak.
        Worse than the memory: the tables are keyed by a *16-bit* sequence
        number, so an entry left behind is not merely dead, it is a mine --
        65,536 requests later the counter comes round to it and it is applied
        to an unrelated reply.
        """

    #: patch_event may return this instead of an event, to withhold it.
    #: Dropping an event is safe in a way dropping a *request* is not: the
    #: server counts requests to generate sequence numbers, so a swallowed
    #: request desynchronises every later reply, while events carry the
    #: sequence of the last request processed and are not counted by the
    #: client.  X itself does not promise a selector every event.
    DROP_EVENT = object()

    def patch_event(self, head):
        """Event to send instead of the server's, DROP_EVENT to withhold it,
        or None to pass it on unchanged."""
        return None

    def patch_generic_event(self, head, body):
        """A generic (XGE) event to send instead, DROP_EVENT to withhold it, or
        None to pass it on unchanged.  Returning a replacement means a
        ``(head, body)`` pair.  The base relay passes everything; the enforcing
        subclass blocks by default and logs, the same default-deny shape the
        request path has."""
        return None

    def server_to_client(self):
        while True:
            head = read_exactly(self.server, 32)
            if head is None:
                break
            kind = head[0]
            if kind == 1:                            # reply
                extra = struct.unpack(self.endian + "I", head[4:8])[0] * 4
                body = read_exactly(self.server, extra) if extra else b""
                if body is None:
                    break
                sequence = struct.unpack(self.endian + "H", head[2:4])[0]
                with self.lock:
                    pending = self.pending.pop(sequence, None)
                if pending is not None:
                    self.resolve(pending, head, body)
                replacement = self.substitution(sequence, head, body)
                self.client.sendall(replacement if replacement is not None
                                    else head + body)
            elif kind == 35:                         # generic event (XGE)
                extra = struct.unpack(self.endian + "I", head[4:8])[0] * 4
                body = read_exactly(self.server, extra) if extra else b""
                if body is None:
                    break
                patched = self.patch_generic_event(head, body)
                if patched is self.DROP_EVENT:
                    continue
                if patched is not None:
                    head, body = patched
                self.client.sendall(head + body)
            else:                                    # error or fixed event
                if kind == 0:                        # failed request: no reply
                    sequence = struct.unpack(self.endian + "H", head[2:4])[0]
                    with self.lock:
                        self.pending.pop(sequence, None)
                    self.discard_sequence(sequence)
                else:
                    patched = self.patch_event(head)
                    if patched is self.DROP_EVENT:
                        continue
                    if patched is not None:
                        head = patched
                self.client.sendall(head)

    # -- lifecycle ---------------------------------------------------------

    def read_replies(self):
        """server_to_client, minus the noise of a closing connection.

        When the client goes away the request thread closes both sockets
        while this one may still be mid-write, so EBADF and friends are
        the normal way this thread ends, not a fault worth reporting.
        """
        try:
            self.server_to_client()
        except (OSError, struct.error):
            pass

    def run(self):
        try:
            if not self.handshake():
                return
            self.profile.note_connection()
            reader = threading.Thread(target=self.read_replies, daemon=True)
            reader.start()
            self.client_to_server()
        except (OSError, struct.error):
            pass
        finally:
            for sock in (self.client, self.server):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass


def listen(display):
    kind, address = parse_display(display)
    if kind == "unix":
        if os.path.exists(address):
            raise SystemExit("%s exists: display %s already in use "
                             "(remove it if the socket is stale)"
                             % (address, display))
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(address)
        # Do not let the ambient umask decide who may connect: the cookie is
        # the real gate, but the socket should not be group- or
        # world-connectable by accident.
        os.chmod(address, 0o600)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(address)
    sock.listen(16)
    return sock, (address if kind == "unix" else None)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--display", default=":20",
                        help="display to offer clients (default :20)")
    parser.add_argument("--upstream", default=os.environ.get("DISPLAY", ":0"),
                        help="real display to forward to (default $DISPLAY)")
    parser.add_argument("--auth", metavar="XAUTHORITY",
                        help="xauth file holding the cookie clients must "
                             "present for --display; omit to accept any")
    parser.add_argument("--upstream-auth", metavar="XAUTHORITY",
                        help="xauth file holding the cookie for --upstream "
                             "(default: $XAUTHORITY, then ~/.Xauthority)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="report every connection and its outcome")
    args = parser.parse_args()
    Connection.verbose = args.verbose

    upstream_target = parse_display(args.upstream)
    _, upstream_cookie = working_cookie(
        upstream_target,
        upstream_candidates(args.upstream_auth, args.upstream))
    expected = (cookie_for(args.auth, args.display, create=True)[1]
                if args.auth else None)
    if not args.auth:
        print("WARNING: --auth was omitted, so %s accepts any local client "
              "and authenticates none of them.  As a profiler that only "
              "reads traffic this is merely permissive; do not run the "
              "policy proxy this way." % args.display,
              file=sys.stderr)

    profile = Profile()
    server, unix_path = listen(args.display)

    def finish(signum, frame):
        profile.dump()
        if unix_path:
            try:
                os.unlink(unix_path)
            except OSError:
                pass
        sys.exit(0)

    signal.signal(signal.SIGINT, finish)
    signal.signal(signal.SIGTERM, finish)

    if args.auth:
        print("\nrun clients with:\n"
              "    export XAUTHORITY=%s\n"
              "    export DISPLAY=%s\n"
              % (os.path.abspath(os.path.expanduser(args.auth)), args.display),
              file=sys.stderr)
    print("listening on %s, forwarding to %s (log only, nothing is denied)"
          % (args.display, args.upstream), file=sys.stderr)
    print("Ctrl-C to print the profile", file=sys.stderr)
    while True:
        client, _ = server.accept()
        Connection(client, upstream_target, upstream_cookie,
                   expected, profile).start()


if __name__ == "__main__":
    main()
