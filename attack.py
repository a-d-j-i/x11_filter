#! /usr/bin/python3
"""The attacks, run twice: straight at the server, and through the proxy.

`e2e.sh` proves the policy does not break real clients.  This proves the other
half -- that the attacks the audit says are closed are still closed -- and it is
the half that had no automated check.  Every finding in AUDIT.md was measured by
hand, once, on the day it was found; nothing re-ran those measurements, so a
later edit could quietly reopen one.  That happened: a fix in the thirteenth
pass closed its own connection, which reset the X server and wiped the atom ids
the proxy had just learned, and nothing noticed until an unrelated measurement
came out strange.

Each check runs the same attack twice and compares:

    CONTROL   straight at the real server -- must succeed, or the check proves
              nothing and is reported INCONCLUSIVE rather than passed.  A
              control that has quietly stopped working is the failure mode this
              discipline exists to catch.
    FILTERED  through the enforcing proxy -- must not succeed.

Run it through attack.sh, which builds the rig.  Exit status is 0 only if every
check PASSED.
"""

import os
import struct
import subprocess
import sys
import time

# -- a minimal X client, so the attacks speak the protocol directly ----------
#
# Deliberately not Xlib: an attack has to be able to send what a toolkit would
# refuse to, name a window it does not own, and skip the polite handshake.


def read_cookie(path):
    with open(path, "rb") as handle:
        blob = handle.read()
    off = 0
    while off + 2 <= len(blob):
        def field(off):
            (n,) = struct.unpack_from(">H", blob, off)
            return blob[off + 2:off + 2 + n], off + 2 + n
        off += 2                                   # family
        _addr, off = field(off)
        _num, off = field(off)
        name, off = field(off)
        data, off = field(off)
        if name == b"MIT-MAGIC-COOKIE-1":
            return data
    raise SystemExit("no MIT-MAGIC-COOKIE-1 in %s" % path)


class Client:
    """One X connection, over a unix socket, with no library in the way."""

    def __init__(self, display, auth):
        import socket
        number = display.lstrip(":").split(".")[0]
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect("/tmp/.X11-unix/X%s" % number)
        cookie, name = read_cookie(auth), b"MIT-MAGIC-COOKIE-1"
        pad = lambda b: b + b"\0" * ((4 - len(b) % 4) % 4)
        self.sock.sendall(struct.pack("<BBHHHH", 0x6c, 0, 11, 0,
                                      len(name), len(cookie)) + b"\0\0"
                          + pad(name) + pad(cookie))
        head = self.recv(8)
        if head[0] != 1:
            raise SystemExit("connection to %s refused" % display)
        body = self.recv(struct.unpack_from("<H", head, 6)[0] * 4)
        self.id_base, self.id_mask = struct.unpack_from("<II", body, 4)
        vendor = struct.unpack_from("<H", body, 16)[0]
        offset = 32 + vendor + (4 - vendor % 4) % 4 + 8 * body[21]
        # every screen, because a second one is where a policy that only knows
        # about the first stops applying
        self.screens = []
        for _ in range(body[20]):
            if len(body) < offset + 40:
                break
            self.screens.append({
                "root": struct.unpack_from("<I", body, offset)[0],
                "width": struct.unpack_from("<H", body, offset + 20)[0],
                "height": struct.unpack_from("<H", body, offset + 22)[0],
                "visual": struct.unpack_from("<I", body, offset + 32)[0],
                "depth": body[offset + 38]})
            depths = body[offset + 39]
            offset += 40
            for _ in range(depths):
                visuals = struct.unpack_from("<H", body, offset + 2)[0]
                offset += 8 + 24 * visuals
        first = self.screens[0]
        self.root, self.root_visual = first["root"], first["visual"]
        self.root_depth = first["depth"]
        self.width, self.height = first["width"], first["height"]
        self.next_id = 0
        self.events = []

    def recv(self, n):
        out = b""
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise SystemExit("connection closed by peer")
            out += chunk
        return out

    def xid(self):
        self.next_id += 1
        return self.id_base | (self.next_id & self.id_mask)

    def send(self, opcode, data=b"", minor=0):
        assert len(data) % 4 == 0, "request body must be padded"
        self.sock.sendall(struct.pack("<BBH", opcode, minor,
                                      1 + len(data) // 4) + data)

    def take(self, timeout=2.0):
        self.sock.settimeout(timeout)
        head = self.recv(32)
        if head[0] == 1:                                   # reply
            extra = struct.unpack_from("<I", head, 4)[0] * 4
            return "reply", head + (self.recv(extra) if extra else b"")
        if head[0] == 0:
            return "error", head
        if head[0] & 0x7F == 35:                           # generic event
            extra = struct.unpack_from("<I", head, 4)[0] * 4
            return "xge", head + (self.recv(extra) if extra else b"")
        return "event", head

    def reply(self, opcode, data=b"", minor=0, timeout=2.0):
        """Send a request and return its reply, or None if it errored."""
        self.send(opcode, data, minor)
        while True:
            kind, message = self.take(timeout)
            if kind == "reply":
                return message
            if kind == "error":
                return None
            self.events.append((kind, message))

    def drain(self, seconds=1.0):
        end = time.time() + seconds
        while time.time() < end:
            try:
                self.events.append(self.take(max(0.05, end - time.time())))
            except (OSError, SystemExit):
                break
        return self.events

    # -- the handful of requests the attacks need --------------------------
    def intern(self, name):
        raw = name.encode()
        body = struct.pack("<HH", len(raw), 0) + raw \
            + b"\0" * ((4 - len(raw) % 4) % 4)
        reply = self.reply(16, body)
        return 0 if reply is None else struct.unpack_from("<I", reply, 8)[0]

    def query_extension(self, name):
        raw = name.encode()
        body = struct.pack("<HH", len(raw), 0) + raw \
            + b"\0" * ((4 - len(raw) % 4) % 4)
        reply = self.reply(98, body)
        if reply is None or not reply[8]:
            return None
        return {"major": reply[9], "first_event": reply[10]}

    def window(self, width, height, x=0, y=0, override=False, mapped=True,
               parent=None, background=None):
        wid = self.xid()
        mask, values = 0, b""
        if background is not None:                 # CWBackPixel, bit 0x2
            mask, values = 0x2, struct.pack("<I", background)
        if override:                               # CWOverrideRedirect, 0x200
            mask, values = mask | 0x200, values + struct.pack("<I", 1)
        body = struct.pack("<IIhhHHHHII", wid, self.root if parent is None
                           else parent, x, y, width, height, 0, 1,
                           self.root_visual, mask) + values
        self.send(1, body, minor=self.root_depth)
        if mapped:
            self.send(8, struct.pack("<I", wid))
        return wid

    def change_property(self, window, prop, data, kind=31, fmt=8):
        count = len(data) if fmt == 8 else len(data) // (fmt // 8)
        body = struct.pack("<IIIBBxxI", window, prop, kind, fmt, 0, count)
        self.send(18, body + data + b"\0" * ((4 - len(data) % 4) % 4))

    def read_property(self, window, atom):
        reply = self.reply(20, struct.pack("<IIIII", window, atom, 0, 0, 4096))
        if reply is None:
            return b""
        return bytes(reply[32:32 + struct.unpack_from("<I", reply, 16)[0]])

    def geometry(self, drawable):
        reply = self.reply(14, struct.pack("<I", drawable))
        if reply is None:
            return (0, 0)
        return struct.unpack_from("<HH", reply, 16)

    def sync(self):
        self.reply(43)                                     # GetInputFocus


# -- the harness -------------------------------------------------------------

class Rig:
    """Where the two runs of each attack happen."""

    def __init__(self):
        self.upstream = os.environ["ATTACK_UPSTREAM"]
        self.upstream_auth = os.environ["ATTACK_UPSTREAM_AUTH"]
        self.proxy = os.environ["ATTACK_PROXY"]
        self.proxy_auth = os.environ["ATTACK_PROXY_AUTH"]
        self.allow_proxy = os.environ.get("ATTACK_ALLOW_PROXY")
        self.allow_auth = os.environ.get("ATTACK_ALLOW_AUTH")
        self.log = os.environ.get("ATTACK_LOG", "")
        # Where a person's hands are.  With a nested server that is the
        # *outer* display: input driven there arrives inside as genuine device
        # input rather than as an XTEST injection into the server under test,
        # which is what a real desktop does.  Xephyr's window sits at the
        # origin of the outer screen, so the coordinates need no translation.
        self.input = os.environ.get("ATTACK_INPUT") or self.upstream
        self.input_auth = (self.upstream_auth
                           if self.input == self.upstream else "")

    def direct(self):
        return Client(self.upstream, self.upstream_auth)

    def filtered(self):
        return Client(self.proxy, self.proxy_auth)

    def permissive(self):
        """A proxy running --gate allow, for the checks that need the user to
        have said yes -- the point being that yes to one thing is not yes to
        everything."""
        return Client(self.allow_proxy, self.allow_auth)

    def hands(self, *arguments, wait=0.25):
        """Do something at the display a person's hands are on."""
        environment = dict(os.environ, DISPLAY=self.input)
        if self.input_auth:
            environment["XAUTHORITY"] = self.input_auth
        else:
            environment.pop("XAUTHORITY", None)
        subprocess.run(["xdotool"] + [str(a) for a in arguments],
                       env=environment, check=False)
        time.sleep(wait)

    def pointer(self, x, y):
        self.hands("mousemove", x, y)

    def key(self, name):
        self.hands("key", name, wait=0.4)

    def type_word(self, word):
        self.hands("type", "--delay", "60", word, wait=0.4)


CHECKS = []

#: Checks that legitimately stay green under `--dry-run`.  Sanitising the
#: proxy's own log output is not a policy decision, so it applies whether or not
#: the policy is enforcing; every other check must go red with enforcement off,
#: or it is proving nothing.
SELFTEST_STAYS_GREEN = {"forging a line of the operation log"}


def check(name, note="", control=True):
    """Register an attack.  The function is called with (rig, connect) where
    connect() opens a client -- direct on the control run, filtered on the
    other -- and returns what the attacker learned or achieved.

    control=False marks an attack with no meaningful direct run, because what
    it targets exists only when a proxy is in the path (the operation log).
    Such a check is judged on the filtered run alone, and says so."""
    def register(function):
        CHECKS.append((name, note, function, control))
        return function
    return register


# -- the denied extensions -------------------------------------------------
#
# These need a server that *has* them, which is why the suite grew an
# ATTACK_SERVER axis: Xvfb offers almost none of this, so on Xvfb the controls
# fail and the checks say INCONCLUSIVE -- correctly, since an attack the server
# cannot mount proves nothing about the policy.  Under Xephyr, which is
# Xorg-derived, every one of them is there to be tried.

try:                                     # the claim under test, from the source
    from xfilter import KNOWN_DENIED_EXTENSIONS as DENIED
except ImportError:                      # ...or its own copy, if run elsewhere
    DENIED = {"XTEST", "RECORD", "MIT-SHM", "Composite", "DAMAGE", "GLX",
              "DRI3", "Present", "XVideo", "SECURITY"}


@check("the denied extensions, by name", "QueryExtension must not find them")
def _denied_extensions(rig, connect):
    client = connect()
    return sorted(name for name in DENIED if client.query_extension(name))


@check("XTEST: typing into the session", "input injection, the write direction")
def _xtest_fake_key(rig, connect):
    client = connect()
    xtest = client.query_extension("XTEST")
    if not xtest:
        # Hidden is the policy working, but this check is about whether the
        # *keystroke* lands, so try the opcode anyway: major opcodes are
        # stable and guessable, which is the whole reason the proxy learns
        # them rather than trusting QueryExtension.
        known = rig.direct().query_extension("XTEST")
        if not known:
            return ""                    # the server has no XTEST at all
        major = known["major"]
    else:
        major = xtest["major"]

    def fake(kind, keycode):             # XTestFakeInput
        client.send(major, struct.pack("<BBxxII8xhh7xB", kind, keycode, 0,
                                       client.root, 0, 0, 0), minor=2)
    fake(2, 38)                          # KeyPress of whatever keycode 38 is
    client.sync()
    time.sleep(0.3)
    oracle = rig.direct()                # ask the server, not the proxy
    keymap = oracle.reply(44)
    down = sum(bin(byte).count("1") for byte in keymap[8:40]) if keymap else 0
    fake(3, 38)                          # KeyRelease, whatever happened
    client.sync()
    time.sleep(0.2)
    return "a key went down in the session" if down else ""


@check("Composite: capturing another window's pixmap",
       "the capture route that needs a real server")
def _composite_capture(rig, connect):
    victim = rig.direct()
    window = victim.window(120, 90, background=0x00FF00)
    victim.sync()
    time.sleep(0.5)
    truth = victim.reply(73, struct.pack("<IhhHHI", window, 0, 0, 16, 16,
                                         0xFFFFFFFF), minor=2)
    truth = truth[32:] if truth else b""
    if len(set(truth)) < 2 and not truth:
        return ""

    client = connect()
    composite = client.query_extension("Composite")
    if not composite:
        known = rig.direct().query_extension("Composite")
        if not known:
            return ""                    # no Composite here to abuse
        major = known["major"]
    else:
        major = composite["major"]
    client.reply(major, struct.pack("<II", 0, 4), minor=0)      # QueryVersion
    client.send(major, struct.pack("<IBxxx", window, 1), minor=1)  # Redirect
    pixmap = client.xid()
    client.send(major, struct.pack("<II", window, pixmap), minor=6)  # NameWindowPixmap
    client.sync()
    time.sleep(0.3)
    reply = client.reply(73, struct.pack("<IhhHHI", pixmap, 0, 0, 16, 16,
                                         0xFFFFFFFF), minor=2)
    got = reply[32:] if reply else b""
    return "%d bytes of another window" % len(got) if got == truth and got else ""


# -- screen capture and input, the core purpose (passes 1-6) -----------------

@check("GetImage(root)", "the screenshot primitive")
def _capture_root(rig, connect):
    client = connect()
    reply = client.reply(73, struct.pack("<IhhHHI", client.root, 0, 0, 32, 32,
                                         0xFFFFFFFF), minor=2)
    return len(reply) - 32 if reply else 0


@check("GetImage(another window)", "reading a trusted window's pixels")
def _capture_window(rig, connect):
    # Open and close a few filtered connections first.  The X server reuses a
    # departed client's resource-id range, so this is what makes the trusted
    # victim below likely to *inherit* a range the proxy has served -- which is
    # how this check caught the proxy still calling that range its own.
    for _ in range(3):
        connect().sock.close()
    victim = rig.direct()
    window = victim.window(200, 150)
    victim.sync()
    time.sleep(0.3)
    client = connect()
    reply = client.reply(73, struct.pack("<IhhHHI", window, 0, 0, 32, 32,
                                         0xFFFFFFFF), minor=2)
    return len(reply) - 32 if reply else 0


@check("CopyArea from a drawable we do not own",
       "the capture route around GetImage")
def _copy_area(rig, connect):
    # Counting the bytes read back proves nothing: a pixmap the copy never
    # reached still answers its full size, in whatever it happened to contain.
    # The question is whether those bytes are the *screen*, so the check
    # compares them against what the screen really holds -- and the screen has
    # to hold something.  Against a black root a pixmap the copy never reached
    # reads back identical to a captured one, and the check accuses the policy
    # of a leak it does not have.  Getting this staging right took three
    # tries, and each wrong one accused the policy: first the region was flat
    # black, then the marker window the check painted was placed elsewhere by
    # the window manager, then -- with the marker at the origin -- the copy
    # read back blank anyway, because a window's own contents *underneath its
    # children* are undefined and the marker was the child.  So the pattern
    # goes on the root itself (attack.sh paints one with xsetroot), and the
    # premise is verified rather than assumed: if the region is one flat
    # colour, the check reports nothing and is INCONCLUSIVE rather than a
    # pass or an accusation.
    # A fourth environment broke it again: under a *compositing* window manager
    # the root reads as one flat colour, because the compositor paints
    # somewhere else -- so the check went honestly INCONCLUSIVE and proved
    # nothing under metacity.  The source is therefore whichever drawable this
    # rig actually has content in: the root if it has a pattern, and otherwise
    # a trusted client's window with something drawn into it.  Both are
    # drawables the attacker does not own, which is the rule under test.
    oracle = rig.direct()

    def image_of(drawable):
        reply = oracle.reply(73, struct.pack("<IhhHHI", drawable, 0, 0, 32, 32,
                                             0xFFFFFFFF), minor=2)
        return reply[32:] if reply else b""

    source, what = oracle.root, "the screen"
    truth = image_of(oracle.root)
    if len(set(truth)) < 2:                # a compositor, or a blank desktop
        window = oracle.window(64, 64, background=0x0000FF)
        gc = oracle.xid()
        oracle.send(55, struct.pack("<IIII", gc, window, 0x4, 0x00FF00))
        oracle.sync()
        time.sleep(0.5)
        oracle.send(70, struct.pack("<IIhhHH", window, gc, 0, 0, 16, 32))
        oracle.sync()
        time.sleep(0.4)
        source, what = window, "a trusted window"
        truth = image_of(window)
        if len(set(truth)) < 2:
            return ""                      # nothing anywhere worth capturing

    client = connect()
    pixmap, gc = client.xid(), client.xid()
    client.send(53, struct.pack("<IIHH", pixmap, client.root, 32, 32),
                minor=client.root_depth)
    client.send(55, struct.pack("<III", gc, pixmap, 0))
    client.send(62, struct.pack("<IIIhhhhHH", source, pixmap, gc,
                                0, 0, 0, 0, 32, 32))
    client.sync()
    reply = client.reply(73, struct.pack("<IhhHHI", pixmap, 0, 0, 32, 32,
                                         0xFFFFFFFF), minor=2)
    got = reply[32:] if reply else b""
    return "%d bytes of %s" % (len(got), what) if got and got == truth else ""


@check("QueryKeymap", "the global key-down bitmap")
def _query_keymap(rig, connect):
    rig.hands("keydown", "a", wait=0.4)
    client = connect()
    reply = client.reply(44)
    rig.hands("keyup", "a")
    return sum(bin(byte).count("1") for byte in reply[8:40]) if reply else 0


# -- the pointer position (ninth pass, corrected in the twelfth) -------------

def focus_elsewhere(rig):
    """Give a *trusted* application the focus and return it.

    Without this the attacker's own window is what the window manager focuses,
    so the keys it receives are keys the user aimed at it -- which is not the
    attack.  The threat is the keystrokes typed into somebody else's window,
    so somebody else has to hold the focus.
    """
    victim = rig.direct()
    window = victim.window(300, 200)
    victim.sync()
    time.sleep(0.4)
    # SetInputFocus: revert-to in the header's data byte, then focus and time
    victim.send(42, struct.pack("<II", window, 0), minor=1)
    victim.sync()
    time.sleep(1.5)          # let the window manager settle on the new focus
    return victim


@check("GrabKeyboard on our own window", "a keylogger that names nothing else")
def _keyboard_grab(rig, connect):
    client = connect()
    window = client.window(80, 60)
    client.sync()
    time.sleep(0.3)
    # owner-events in the header's data byte; grab window, time, the two modes
    reply = client.reply(31, struct.pack("<IIBBxx", window, 0, 1, 1))
    granted = bool(reply) and reply[1] == 0                  # 0 == Success
    keeper = focus_elsewhere(rig)  # noqa: F841 -- held, not used: dropping
    #                                the name closes the connection whose
    #                                window holds the focus we just moved
    rig.type_word("secret")
    keys = [message[1] for kind, message in client.drain(1.0)
            if kind == "event" and message[0] & 0x7F == 2]   # KeyPress
    client.send(32, struct.pack("<I", 0))                    # UngrabKeyboard
    client.sync()
    return "%d keystrokes: %s" % (len(keys), keys) if granted and keys else ""


@check("GrabPointer, then watch the desktop", "the trace a grab delivers")
def _pointer_grab(rig, connect):
    client = connect()
    window = client.window(40, 30, x=0, y=0, override=True)
    client.sync()
    time.sleep(0.3)
    client.reply(26, struct.pack("<IHBBIII", window, 0x4 | 0x8 | 0x40,
                                 1, 1, 0, 0, 0))
    seen = []
    for x, y in ((200, 150), (700, 500), (1100, 800)):
        rig.pointer(x, y)
    for kind, message in client.drain(1.0):
        if kind == "event" and message[0] & 0x7F == 6:       # MotionNotify
            position = struct.unpack_from("<hh", message, 20)
            if position != (0, 0):
                seen.append(position)
    client.send(27, struct.pack("<I", 0))                    # UngrabPointer
    client.sync()
    # only positions away from the client's own corner window are the finding
    far = [p for p in seen if p[0] > 100 or p[1] > 100]
    return "the pointer traced to %s" % (far[-1],) if far else ""


@check("XIGrabDevice: the same grab through XInput2",
       "the door a modern toolkit actually uses")
def _xi_keyboard_grab(rig, connect):
    client = connect()
    xi = client.query_extension("XInputExtension") \
        or rig.direct().query_extension("XInputExtension")
    if not xi:
        return ""
    major = xi["major"]
    client.reply(major, struct.pack("<HH", 2, 3), minor=47)   # XIQueryVersion
    window = client.window(80, 60)
    client.sync()
    time.sleep(0.3)
    keys_wanted = (1 << 2) | (1 << 3)
    reply = client.reply(major, struct.pack("<IIIHBBBxHI", window, 0, 0, 3, 1,
                                            1, 0, 1, keys_wanted), minor=51)
    granted = bool(reply) and reply[8] == 0
    keeper = focus_elsewhere(rig)  # noqa: F841 -- held, not used: dropping
    #                                the name closes the connection whose
    #                                window holds the focus we just moved
    rig.type_word("secret")
    keys = [struct.unpack_from("<I", message, 16)[0]
            for kind, message in client.drain(1.2)
            if kind == "xge" and struct.unpack_from("<H", message, 8)[0] == 2]
    client.send(major, struct.pack("<HH", 3, 0), minor=52)    # XIUngrabDevice
    client.sync()
    return "%d keystrokes: %s" % (len(keys), keys) if granted and keys else ""


@check("the scrub after the sequence counter wraps",
       "70,000 requests later, is the policy still there?")
def _after_the_wrap(rig, connect):
    client = connect()
    # The policy keys its substitutions by a *16-bit* sequence number.  Nothing
    # had ever asked what happens when that counter comes round -- the twelfth
    # pass fixed a table that leaked entries on error paths partly because such
    # an entry outlives the wrap, but the wrap itself was never exercised.
    for index in range(70000):
        client.send(43)                              # GetInputFocus
        if index % 5000 == 0:
            client.reply(43)                         # keep the socket drained
    client.reply(43)
    rig.hands("keydown", "a", wait=0.4)
    keymap = client.reply(44)                        # QueryKeymap
    rig.hands("keyup", "a")
    down = sum(bin(byte).count("1") for byte in keymap[8:40]) if keymap else 0
    # A verdict, not a count.  Returning "%d keys" let the self-test score a
    # false PASS: with the policy off, the direct and filtered runs both
    # leaked, but they leaked *different numbers* of keys -- a key plus a
    # modifier here, one fewer there -- and two different strings read as "the
    # proxy changed something".  A check must answer what the attack achieved.
    return "the keyboard is readable past the wrap" if down else ""


@check("QueryPointer(root)", "how every toolkit asks where the mouse is")
def _pointer_root(rig, connect):
    rig.pointer(640, 450)
    client = connect()
    reply = client.reply(38, struct.pack("<I", client.root))
    return struct.unpack_from("<hh", reply, 16) if reply else (0, 0)


@check("QueryPointer(big unmapped own window)", "a measuring stick, not a window")
def _pointer_unmapped(rig, connect):
    rig.pointer(700, 500)
    client = connect()
    stick = client.window(client.width, client.height, mapped=False)
    client.sync()
    reply = client.reply(38, struct.pack("<I", stick))
    return struct.unpack_from("<hh", reply, 16) if reply else (0, 0)


@check("QueryPointer via a second connection", "the two-connection split")
def _pointer_two_connections(rig, connect):
    first, second = connect(), connect()
    window = first.window(40, 30)
    first.sync()
    rig.pointer(700, 500)
    reply = second.reply(38, struct.pack("<I", window))
    return struct.unpack_from("<hh", reply, 16) if reply else (0, 0)


# -- the desktop-spoof defence (fifth pass; twelfth and thirteenth) ----------

#: How long to let a window manager honour a state change before concluding it
#: never will.
#:
#: Twenty-seventh pass.  These measurements used a fixed sleep and then looked
#: once, on the assumption that a manager acts on _NET_WM_STATE inside it.  A
#: *compositing* manager in a nested server sometimes does not, so the same
#: attack came out red on one run and green on the next: measured over six runs
#: of `--dry-run` on xephyr+metacity, the count of checks that went red moved
#: between 25 and 27 with nothing changing but the weather.  That is fatal to a
#: self-test whose whole claim is "every check must go red", because there is
#: then no number to compare against and a check that has quietly stopped
#: working is indistinguishable from a slow window manager.  So: wait for the
#: answer instead of guessing how long it takes.  A run where the attack
#: genuinely fails pays the whole timeout, which is the right way round -- the
#: suite is allowed to be slow, it is not allowed to be flaky.
SETTLE_SECONDS = 3.0


def _settled(oracle, measure):
    """Poll a measurement until it reports something, or give up on it."""
    deadline = time.time() + SETTLE_SECONDS
    while True:
        answer = measure(oracle)
        if answer or time.time() >= deadline:
            return answer
        time.sleep(0.2)


def covers_the_screen(rig, window):
    """Whether the window manager actually made it fullscreen.

    A check must report what the *attack* achieved, not a raw measurement:
    returning the geometry meant that with RIG_WM=none -- nobody to honour the
    request -- the control and the filtered run agreed on "still 300x200" and
    the harness read that as the policy failing, when the truth is that the rig
    could not mount the attack at all.  Empty means "did not go fullscreen",
    which is what INCONCLUSIVE is built on.
    """
    def look(oracle):
        width, height = oracle.geometry(window)
        return ("%dx%d" % (width, height)
                if width >= oracle.width * 0.9 and height >= oracle.height * 0.9
                else "")
    return _settled(rig.direct(), look)


def borderless_fullscreen(rig, window):
    """What the spoof gate exists to prevent: a window that covers the screen
    *and* bypasses the window manager.  A framed window the size of the
    workarea is an ordinary maximised window, not a fake desktop."""
    def look(oracle):
        width, height = oracle.geometry(window)
        attributes = oracle.reply(3, struct.pack("<I", window))
        override = attributes[27] if attributes else 0
        covers = width >= oracle.width * 0.9 and height >= oracle.height * 0.9
        return ("%dx%d, override-redirect" % (width, height)
                if covers and override else "")
    return _settled(rig.direct(), look)


@check("fullscreen override-redirect window", "a borderless fake desktop")
def _fullscreen_override(rig, connect):
    client = connect()
    window = client.window(client.width, client.height, override=True)
    client.sync()
    return borderless_fullscreen(rig, window)


@check("fullscreen by _NET_WM_STATE, atoms named", "the EWMH route")
def _fullscreen_named(rig, connect):
    client = connect()
    state = client.intern("_NET_WM_STATE")
    full = client.intern("_NET_WM_STATE_FULLSCREEN")
    window = client.window(300, 200, mapped=False)
    client.change_property(window, state, struct.pack("<I", full),
                           kind=4, fmt=32)
    client.send(8, struct.pack("<I", window))
    client.sync()
    return covers_the_screen(rig, window)


@check("fullscreen by _NET_WM_STATE, atoms never named",
       "the same, by id, so no rule can recognise it")
def _fullscreen_by_id(rig, connect):
    oracle = rig.direct()                       # stands in for _NET_SUPPORTED
    state, full = oracle.intern("_NET_WM_STATE"), \
        oracle.intern("_NET_WM_STATE_FULLSCREEN")
    client = connect()
    window = client.window(300, 200, mapped=False)
    client.change_property(window, state, struct.pack("<I", full),
                           kind=4, fmt=32)
    client.send(8, struct.pack("<I", window))
    client.sync()
    return covers_the_screen(rig, window)


@check("a fake desktop tiled out of four windows",
       "none of them fullscreen, together the screen")
def _fullscreen_tiled(rig, connect):
    colour = 0x00AA00
    client = connect()
    half_w, half_h = client.width // 2, client.height // 2
    for x, y in ((0, 0), (half_w, 0), (0, half_h), (half_w, half_h)):
        client.window(half_w, half_h, x=x, y=y, override=True,
                      background=colour)
    client.sync()
    time.sleep(1.0)

    oracle = rig.direct()                       # what the screen really shows
    quadrants = 0
    for x, y in ((100, 100), (client.width - 100, 100),
                 (100, client.height - 100),
                 (client.width - 100, client.height - 100)):
        reply = oracle.reply(73, struct.pack("<IhhHHI", oracle.root, x, y, 2, 2,
                                             0xFFFFFFFF), minor=2)
        if reply and struct.unpack_from("<I", reply, 32)[0] & 0xFFFFFF == colour:
            quadrants += 1
    # Only a *whole* screen is the attack: what the policy still allows is the
    # partial-coverage spoof it has always documented, and no more than a
    # single permitted window could cover on its own.
    return "the whole screen is the attacker's" if quadrants == 4 else ""


@check("a fake desktop on the second screen",
       "the gate measured every window against the first")
def _fullscreen_second_screen(rig, connect):
    client = connect()
    if len(client.screens) < 2:
        return ""                      # a one-screen rig proves nothing here
    screen = client.screens[1]
    wid = client.xid()
    client.send(1, struct.pack("<IIhhHHHHIII", wid, screen["root"], 0, 0,
                               screen["width"], screen["height"], 0, 1,
                               screen["visual"], 0x200, 1),
                minor=screen["depth"])
    client.send(8, struct.pack("<I", wid))
    client.sync()
    time.sleep(0.6)
    oracle = rig.direct()
    width, height = oracle.geometry(wid)
    attributes = oracle.reply(3, struct.pack("<I", wid))
    override = attributes[27] if attributes else 0
    return ("%dx%d, override-redirect, on screen 1" % (width, height)
            if override and width >= screen["width"] else "")


@check("fullscreen assembled on two connections", "the two-connection split")
def _fullscreen_two_connections(rig, connect):
    first, second = connect(), connect()
    window = first.window(100, 100, override=True)
    first.sync()
    second.send(12, struct.pack("<IHHII", window, 0x4 | 0x8, 0,
                                first.width, first.height))
    second.sync()
    return borderless_fullscreen(rig, window)


# -- keyboard state (ninth and eleventh passes; thirteenth) ------------------

@check("XKB events without QueryExtension",
       "the extension's event base, used without asking for it")
def _xkb_events_impolite(rig, connect):
    known = rig.direct().query_extension("XKEYBOARD")
    if not known:
        return "no XKEYBOARD"
    client = connect()
    # deliberately no QueryExtension: the opcode is stable and guessable
    client.reply(known["major"], struct.pack("<HH", 1, 0), minor=0)
    client.send(known["major"],
                struct.pack("<HHHHHH", 0x0100, 0x0FFF, 0, 0x0FFF, 0, 0), minor=1)
    client.sync()
    rig.key("Caps_Lock")
    leaked = sorted({message[1] for kind, message in client.drain(1.2)
                     if kind == "event"
                     and message[0] & 0x7F == known["first_event"]
                     and message[1] not in (0, 1)})
    rig.key("Caps_Lock")
    return leaked


@check("keyboard lock state, five ways", "Caps Lock is a key the user pressed")
def _lock_state(rig, connect):
    rig.key("Caps_Lock")
    try:
        client = connect()
        found = []
        led = client.reply(103)                            # GetKeyboardControl
        if led and struct.unpack_from("<I", led, 8)[0]:
            found.append("GetKeyboardControl")
        xkb = client.query_extension("XKEYBOARD")
        if xkb:
            major = xkb["major"]
            client.reply(major, struct.pack("<HH", 1, 0), minor=0)
            state = client.reply(major, struct.pack("<HH", 0x0100, 0), minor=12)
            if state and struct.unpack_from("<I", state, 8)[0]:
                found.append("XkbGetIndicatorState")
            caps = client.intern("Caps Lock")
            named = client.reply(major, struct.pack("<HHHHI", 0x0100, 0, 0, 0,
                                                    caps), minor=15)
            if named and named[13]:
                found.append("XkbGetNamedIndicator")
        xi = client.query_extension("XInputExtension")
        if xi:
            client.reply(xi["major"], struct.pack("<HH", 2, 2), minor=1)
            feedback = client.reply(xi["major"],
                                    struct.pack("<BBBB", 3, 0, 0, 0), minor=22)
            if feedback:
                count, offset = struct.unpack_from("<H", feedback, 8)[0], 32
                for _ in range(count):
                    if offset + 16 > len(feedback):
                        break
                    length = struct.unpack_from("<H", feedback, offset + 2)[0]
                    if feedback[offset] == 0 and \
                            struct.unpack_from("<I", feedback, offset + 8)[0]:
                        found.append("GetFeedbackControl")
                    if length < 4:
                        break
                    offset += length
        return found
    finally:
        rig.key("Caps_Lock")


# -- who is doing what (ninth and eleventh passes) ---------------------------

@check("GetSelectionOwner(CLIPBOARD)", "polled, a trace of every copy")
def _selection_owner(rig, connect):
    holder = rig.direct()
    window = holder.window(10, 10, mapped=False)
    clipboard = holder.intern("CLIPBOARD")
    holder.send(22, struct.pack("<III", window, clipboard, 0))
    holder.sync()
    client = connect()
    reply = client.reply(23, struct.pack("<I", client.intern("CLIPBOARD")))
    owner = struct.unpack_from("<I", reply, 8)[0] if reply else 0
    return "the real owner" if owner == window else "0x%x" % owner


@check("GetInputFocus", "which window the user is working in")
def _input_focus(rig, connect):
    holder = rig.direct()
    window = holder.window(100, 100)
    holder.sync()
    time.sleep(0.3)
    holder.send(42, struct.pack("<IIx3x", window, 0))      # SetInputFocus
    holder.sync()
    time.sleep(0.3)
    client = connect()
    reply = client.reply(43)
    focus = struct.unpack_from("<I", reply, 8)[0] if reply else 0
    return "the real focus" if focus == window else "0x%x" % focus


@check("QueryTree(root)", "enumerating everyone's windows")
def _query_tree(rig, connect):
    rig.direct().window(50, 50)
    time.sleep(0.3)
    client = connect()
    reply = client.reply(15, struct.pack("<I", client.root))
    return struct.unpack_from("<H", reply, 16)[0] if reply else 0


@check("GetProperty(WM_NAME) on another window", "another app's title")
def _foreign_title(rig, connect):
    victim = rig.direct()
    window = victim.window(80, 60)
    victim.change_property(window, 39, b"a private title")   # WM_NAME
    victim.sync()
    time.sleep(0.3)
    client = connect()
    return client.read_property(window, 39)


# -- selections as capabilities (fourteenth pass) ----------------------------

@check("ConvertSelection into another window",
       "having a trusted owner write where you may not")
def _convert_into_foreign(rig, connect):
    owner = rig.direct()
    owner_window = owner.window(10, 10, mapped=False)
    selection = owner.intern("ATTACK_SELECTION")
    owner.send(22, struct.pack("<III", owner_window, selection, 0))
    owner.sync()

    victim = rig.direct()
    target = victim.window(10, 10, mapped=False)
    victim.sync()

    client = connect()
    prop = client.intern("ATTACK_PROPERTY")
    client.send(24, struct.pack("<IIIII", target,
                                client.intern("ATTACK_SELECTION"), 31, prop, 0))
    client.sync()
    # the owner answers the way ICCCM says: write into the requestor's property
    deadline = time.time() + 2.0
    while time.time() < deadline:
        try:
            kind, message = owner.take(0.5)
        except (OSError, SystemExit):
            break
        if kind == "event" and message[0] & 0x7F == 30:     # SelectionRequest
            requestor = struct.unpack_from("<I", message, 12)[0]
            wanted = struct.unpack_from("<I", message, 24)[0]
            owner.change_property(requestor, wanted, b"the owner's data")
            owner.sync()
            break
    time.sleep(0.3)
    return victim.read_property(target, prop)


@check("minting a selection grant", "--gate allow", )
def _mint_grant(rig, connect):
    victim = rig.direct()
    target = victim.window(10, 10, mapped=False)
    victim.sync()
    client = connect()
    clipboard = client.intern("CLIPBOARD")
    prop = client.intern("GRANT_PROPERTY")
    client.send(22, struct.pack("<III", client.window(10, 10, mapped=False),
                                clipboard, 0))               # own the clipboard
    client.sync()
    # ask the server to send us a SelectionRequest naming a window of our choice
    client.send(24, struct.pack("<IIIII", target, clipboard, 31, prop, 0))
    client.sync()
    client.drain(0.6)
    client.change_property(target, prop, b"minted")
    client.sync()
    time.sleep(0.3)
    return victim.read_property(target, prop)


# -- what the proxy says about a client (twelfth pass) -----------------------

@check("forging a line of the operation log", "a newline in WM_CLASS",
       control=False)
def _log_forgery(rig, connect):
    client = connect()
    window = client.window(10, 10, mapped=False)
    forged = ("xterm\nnew operation: core:GetImage    allowed  trusted "
              "desktop app [local pid 1, uid 0]")
    client.change_property(window, client.intern("WM_CLASS"),
                           forged.encode() + b"\0")
    client.reply(15, struct.pack("<I", 0x5000489))     # trip a logged decision
    client.sync()
    time.sleep(0.5)
    if not rig.log or not os.path.exists(rig.log):
        return "no log"
    with open(rig.log) as handle:
        lines = handle.read().splitlines()
    return [line for line in lines
            if line.startswith("new operation: core:GetImage")
            and "trusted desktop app" in line]


def run():
    rig = Rig()
    results = []
    for name, note, function, wants_control in CHECKS:
        permissive = note == "--gate allow"
        if permissive and not rig.allow_proxy:
            results.append((name, "SKIP", "", ""))
            continue
        control = "(no direct control)"
        if wants_control:
            try:
                control = function(rig, rig.direct)
            except Exception as exc:                 # a broken control
                control = "error: %s" % exc
        try:
            filtered = function(
                rig, rig.permissive if permissive else rig.filtered)
        except Exception as exc:
            filtered = "error: %s" % exc
        results.append((name, None, control, filtered))

    print("\n%-46s %-26s %-26s" % ("attack", "direct (control)", "through the proxy"))
    print("-" * 100)
    failures = inconclusive = 0
    not_red = []
    for name, verdict, control, filtered in results:
        if verdict == "SKIP":
            print("%-46s %s" % (name, "skipped (no --gate allow proxy)"))
            continue
        empty = (0, (0, 0), [], b"", "", None)
        if control == "(no direct control)":
            verdict = "PASS" if filtered in empty else "FAIL"
            failures += verdict == "FAIL"
        elif control in empty or str(control).startswith("error"):
            verdict, inconclusive = "INCONCLUSIVE", inconclusive + 1
        elif filtered in empty:
            verdict = "PASS"
        elif filtered == control:
            verdict, failures = "FAIL", failures + 1
        else:
            verdict = "PASS"          # answered, but not with the real thing
        if verdict != "FAIL":
            not_red.append(name)
        print("%-46s %-26.25s %-26.25s %s"
              % (name, control, filtered, verdict))
    print("-" * 100)
    print("%d checks, %d failed, %d inconclusive"
          % (len(results), failures, inconclusive))
    if inconclusive:
        print("\nAn INCONCLUSIVE check is not a pass: the attack did not work "
              "even\nwithout the proxy, so it proves nothing about the policy. "
              "Fix the rig.")
    if os.environ.get("ATTACK_SELFTEST"):
        # Twenty-seventh pass.  The self-test used to report a bare count, and
        # a count is not enough to act on: when the number moved between runs
        # there was no way to tell a rig that had got slower from a check that
        # had quietly stopped working, short of standing up the previous
        # revision in a second worktree and diffing -- which is exactly what it
        # cost to clear this pass's own changes.  Naming them makes the
        # difference readable at the point it appears.
        stayed = [n for n in not_red if n not in SELFTEST_STAYS_GREEN]
        print("\nself-test: %d of %d checks went red."
              % (failures, len(results)))
        if stayed:
            print("These did not, so they demonstrated nothing here -- a check "
                  "that cannot go\nred with the policy switched off is not "
                  "evidence about the policy:")
            for name in stayed:
                print("    %s" % name)
        else:
            print("Every check that can go red did.")
    return 1 if failures or inconclusive else 0


if __name__ == "__main__":
    sys.exit(run())
