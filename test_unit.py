#! /usr/bin/python3
"""Unit tests for the policy and the wire parsing. Run: python3 test_unit.py

No X server, no network, no GUI: every test here builds request bytes by
hand and asks the policy what it thinks.  These are the parts that break
quietly -- an offset off by four, or an allowlist entry lost in an edit --
and where a wrong answer is a security hole rather than a crash.
"""

import os
import socket
import struct
import threading
import time

import xfilter
import xfilter_core as core

LE = "<"
BASE, MASK = 0x0400000, 0x1FFFFF
OWN = BASE | 0x11              # an XID this client could have created
FOREIGN = 0x5000489            # one it could not
ROOT = 0x3DC


def make_connection(gate_mode="deny", enforce=True):
    """A PolicyConnection with no sockets: judge() never touches them."""
    profile = xfilter.PolicyProfile()
    profile.note_range(BASE, MASK)
    conn = xfilter.PolicyConnection(None, None, None, None, profile,
                                    enforce=enforce)
    conn.endian = LE
    conn.id_base, conn.id_mask = BASE, MASK
    conn.gate_mode = gate_mode
    conn.alert_new = False        # keep the sentinel quiet during tests
    for atom, name in ((100, "CLIPBOARD"), (101, "_XSETTINGS_S0"),
                       (102, "WM_NAME"), (103, "RESOURCE_MANAGER"),
                       (104, "_NET_WM_STATE"), (105, "GDK_SELECTION"),
                       (106, "_XSETTINGS_SETTINGS")):
        profile.note_atom(atom, name)
    return conn


def convert_selection(requestor, selection, target=31, prop=200):
    return struct.pack(LE + "IIII I", requestor, selection, target, prop, 0)


def get_property(window, prop):
    return struct.pack(LE + "IIIII", window, prop, 0, 0, 0)


def send_event(destination, code, message_atom=0):
    event = bytearray(32)
    event[0] = code
    struct.pack_into(LE + "I", event, 8, message_atom)
    return struct.pack(LE + "II", destination, 0) + bytes(event)


# -- ownership -------------------------------------------------------------

def test_foreign_is_about_ranges_not_connections():
    profile = xfilter.PolicyProfile()
    profile.note_range(BASE, MASK)
    assert profile.is_foreign(FOREIGN)
    assert not profile.is_foreign(OWN)
    assert not profile.is_foreign(0)          # None/AnyPropertyType
    # a sibling connection of the same application must not read as foreign
    profile.note_range(FOREIGN & ~MASK, MASK)
    assert not profile.is_foreign(FOREIGN)


# -- selections ------------------------------------------------------------

def test_clipboard_is_gated_and_settings_are_not():
    conn = make_connection()
    verdict, _ = conn.judge(24, 0, convert_selection(OWN, 100))
    assert verdict == "gate"
    verdict, _ = conn.judge(24, 0, convert_selection(OWN, 101))
    assert verdict == "allow", "theming must survive the policy"


def test_gate_modes():
    assert make_connection("allow").judge(24, 0,
                                          convert_selection(OWN, 100))[0] == "allow"
    conn = make_connection("ask")
    conn.gate = object()                      # judge only checks it exists
    assert conn.judge(24, 0, convert_selection(OWN, 100))[0] == "ask"


def test_gated_request_is_rewritten_to_an_unowned_atom():
    conn = make_connection()
    sent = []
    conn.server = type("S", (), {"sendall": lambda _self, data: sent.append(data)})()
    body = convert_selection(OWN, 100)          # target 31, property 200
    conn.forward(24, 0, struct.pack(LE + "BBH", 24, 0, 6), body)
    rewritten = struct.unpack_from(LE + "I", sent[0], 8)[0]
    assert rewritten == xfilter.UNOWNED_ATOM
    # keyed on (requestor, target), so the refused SelectionNotify -- which
    # comes back with property None -- can still be matched
    assert conn.gated[(OWN, 31)] == 100, "the original atom must be recoverable"


# -- properties ------------------------------------------------------------

def test_foreign_property_reads():
    conn = make_connection()
    verdict, _ = conn.judge(20, 0, get_property(FOREIGN, 102))     # WM_NAME
    assert callable(verdict), "window titles of other clients must be refused"
    verdict, _ = conn.judge(20, 0, get_property(ROOT, 103))        # RESOURCE_MANAGER
    assert verdict == "allow", "cursor theme and DPI must survive"
    verdict, _ = conn.judge(20, 0, get_property(FOREIGN, 106))     # XSETTINGS
    assert verdict == "allow"
    verdict, _ = conn.judge(20, 0, get_property(OWN, 102))
    assert verdict == "allow", "a client may always read its own windows"


def test_writing_foreign_properties_needs_a_selection_request():
    conn = make_connection()
    body = struct.pack(LE + "IIIII", FOREIGN, 105, 31, 8, 4) + b"data"
    assert conn.judge(18, 0, body)[0] == "silent"
    conn.grant_selection(FOREIGN, 105)
    assert conn.judge(18, 0, body)[0] == "allow", "paste out must work"


# -- events and capture ----------------------------------------------------

def test_send_event_rules():
    conn = make_connection()
    assert conn.judge(25, 0, send_event(ROOT, 33, 104))[0] == "allow"   # EWMH
    assert conn.judge(25, 0, send_event(ROOT, 33, 102))[0] == "silent"  # not EWMH
    assert conn.judge(25, 0, send_event(FOREIGN, 31))[0] == "silent"
    conn.grant_selection(FOREIGN, 0)
    assert conn.judge(25, 0, send_event(FOREIGN, 31))[0] == "allow", \
        "answering a selection request must reach the asker"


def test_capture_and_grabs():
    conn = make_connection()
    assert callable(conn.judge(73, 0, struct.pack(LE + "I", FOREIGN))[0])
    assert conn.judge(73, 0, struct.pack(LE + "I", OWN))[0] == "allow"
    assert conn.judge(62, 0, struct.pack(LE + "II", FOREIGN, OWN))[0] == "silent"
    assert callable(conn.judge(31, 0, struct.pack(LE + "I", ROOT))[0])


def test_input_taps_on_foreign_windows():
    conn = make_connection()
    mask = xfilter.CW_EVENT_MASK
    tap = struct.pack(LE + "III", FOREIGN, mask, 0x1)          # KeyPress
    # The foreign-window event mask is an allowlist now: StructureNotify pushes
    # another window's geometry and is refused with every other unlisted bit;
    # only PropertyChange (for XSETTINGS/_NET_*) is allowed.
    structure = struct.pack(LE + "III", FOREIGN, mask, 0x20000)   # StructureNotify
    prop = struct.pack(LE + "III", FOREIGN, mask, 0x400000)       # PropertyChange
    assert conn.judge(2, 0, tap)[0] == "silent"
    assert conn.judge(2, 0, structure)[0] == "silent"
    assert conn.judge(2, 0, prop)[0] == "allow"


# -- extensions ------------------------------------------------------------

def test_extension_list_is_filtered():
    conn = make_connection()
    names = [b"XTEST", b"RENDER", b"RECORD", b"SHAPE", b"X-Resource"]
    packed = b"".join(bytes([len(n)]) + n for n in names)
    packed += b"\0" * core.pad4(len(packed))
    head = bytearray(32)
    head[0], head[1] = 1, len(names)
    struct.pack_into(LE + "I", head, 4, len(packed) // 4)
    reply = conn.filter_extension_list(bytes(head), packed)

    assert reply[1] == 2, "XTEST, RECORD and X-Resource should be gone"
    body = reply[32:]
    assert b"RENDER" in body and b"SHAPE" in body
    assert b"XTEST" not in body and b"RECORD" not in body
    assert b"X-Resource" not in body, "neither denied nor allowed is not shown"
    assert struct.unpack_from(LE + "I", reply, 4)[0] * 4 == len(body)
    assert len(body) % 4 == 0, "replies must stay word-aligned"


# -- the gate's flood control ----------------------------------------------

def test_denial_is_remembered_and_duplicates_collapse():
    gate = xfilter.Gate(timeout=0, remember=300)
    prompts = []

    def answer_once():
        identity, selection, target, peer, action, answer, answered = \
            gate.requests.get(timeout=2)
        prompts.append(identity)
        answer["allow"] = False
        answered.set()

    threading.Thread(target=answer_once, daemon=True).start()
    # the same connection token asking twice: one dialog, one remembered answer
    assert gate.decide(1, "app", "CLIPBOARD", "STRING", "local pid 7") is False
    assert gate.decide(1, "app", "CLIPBOARD", "STRING", "local pid 7") is False
    assert len(prompts) == 1, "a refusal has to buy quiet"


def test_pending_prompts_are_capped():
    gate = xfilter.Gate(timeout=0, remember=300)
    for n in range(gate.MAX_PENDING):
        gate.requests.put((str(n), "CLIPBOARD", "STRING", "peer", "read", {},
                           threading.Event()))
    assert gate.decide(99, "flooder", "CLIPBOARD", "STRING", "peer") is False
    assert gate.requests.qsize() == gate.MAX_PENDING, "no dialog was queued"


def test_grant_is_not_inherited_by_a_second_connection():
    # A grant remembered for one connection token must not cover another,
    # even if the second claims the same name.
    gate = xfilter.Gate(timeout=0, remember=300)
    gate.decisions[(1, "CLIPBOARD", "read")] = (True, time.time() + 300)
    assert gate.decide(1, "app", "CLIPBOARD", "STRING", "peer") is True
    prompts = []

    def answer_once():
        request = gate.requests.get(timeout=2)
        prompts.append(request[0])
        request[5]["allow"] = False
        request[6].set()

    threading.Thread(target=answer_once, daemon=True).start()
    assert gate.decide(2, "app", "CLIPBOARD", "STRING", "peer") is False, \
        "a different connection must be asked afresh, not handed the grant"
    assert prompts == ["app"]


# -- helpers ---------------------------------------------------------------

def test_display_parsing():
    assert core.parse_display(":20") == ("unix", "/tmp/.X11-unix/X20")
    assert core.parse_display("localhost:20") == ("tcp", ("127.0.0.1", 6020))
    assert core.parse_display("host:1.0") == ("tcp", ("host", 6001))
    assert core.pad4(0) == 0 and core.pad4(1) == 3 and core.pad4(4) == 0


# -- the gated selection matched by id, not just name ---------------

def test_selection_gated_by_hardcoded_atom_id():
    conn = make_connection()
    conn.gated_selection_ids = frozenset({230})    # CLIPBOARD's server-wide id
    # a client that hardcodes 230 and never interns a name for it
    assert conn.judge(24, 0, convert_selection(OWN, 230))[0] == "gate", \
        "a gated selection must be caught by id, not only by a name we saw"
    assert conn.judge(24, 0, convert_selection(OWN, 999))[0] == "allow"


def test_who_owns_the_clipboard_is_answered_with_a_stand_in():
    # Eleventh pass.  XFIXES SelectSelectionInput -- "tell me when the
    # clipboard changes hands" -- is refused as a snoop on a gated selection,
    # while the core poll of the same fact was on SAFE_CORE and answered
    # truthfully: a foreign window id, and, polled, a trace of every copy and
    # mouse-selection on the desktop (PRIMARY changes owner on each one).
    conn = rooted_connection()
    verdict, _ = conn.judge(23, 0, struct.pack(LE + "I", 100))   # CLIPBOARD
    assert isinstance(verdict, tuple) and verdict[0] == "scrub-foreign"
    assert verdict[1] == ([8], xfilter.SELECTION_OWNER_STANDIN), \
        "the owner is at offset 8, and becomes the stand-in when foreign"
    assert conn.judge(23, 0, struct.pack(LE + "I", 1))[0][0] == "scrub-foreign", \
        "PRIMARY is gated by its predefined atom id, not only by name"
    assert conn.judge(23, 0, struct.pack(LE + "I", 105))[0] == "allow", \
        "a selection outside the gated three names a manager, not the clipboard"

    def reply_naming(window):
        head = bytearray(32)
        head[0] = 1
        struct.pack_into(LE + "I", head, 8, window)
        return bytes(head)

    offsets, stand_in = verdict[1]
    foreign = conn.scrub_foreign_windows(reply_naming(FOREIGN), b"",
                                         offsets, stand_in)
    assert struct.unpack_from(LE + "I", foreign, 8)[0] == 0xFFFFFFFF, \
        "another client's ownership reads as an id that is nobody's"
    assert struct.unpack_from(LE + "I", foreign, 8)[0] != 0, \
        "not None: a toolkit reads None as 'nothing to paste' and greys it out"
    own = conn.scrub_foreign_windows(reply_naming(OWN), b"", offsets, stand_in)
    assert struct.unpack_from(LE + "I", own, 8)[0] == OWN, \
        "a client must still see that it owns the selection itself (ICCCM)"


# -- extension argument inspection ------------------------------------------

def xi_select_events(window, mask, device=0):
    return (struct.pack(LE + "IHH", window, 1, 0)
            + struct.pack(LE + "HH", device, 1) + struct.pack(LE + "I", mask))


def test_xinput_raw_key_tap_is_refused():
    conn = make_connection()
    conn.extension_opcodes = {131: "XInputExtension"}
    raw_key = 1 << 13                                   # XI_RawKeyPress
    hierarchy = 1 << 11                                 # XI_HierarchyChanged
    # a raw-key selection on the (foreign) root is the keylogger
    assert conn.judge(131, 46, xi_select_events(ROOT, raw_key))[0] == "silent"
    # the same on a window the client owns is legitimate input handling
    assert conn.judge(131, 46, xi_select_events(OWN, raw_key))[0] == "allow"
    # a benign, non-input event on the root is not a tap
    assert conn.judge(131, 46, xi_select_events(ROOT, hierarchy))[0] == "allow"


def generic_event(major, evtype, extra_words=0):
    head = bytearray(32)
    head[0] = 35                                       # GenericEvent
    head[1] = major
    struct.pack_into(LE + "I", head, 4, extra_words)   # length in 4-byte units
    struct.pack_into(LE + "H", head, 8, evtype)
    return bytes(head), b"\0" * (extra_words * 4)


def test_generic_events_are_default_deny():
    """XGE is the one server-to-client channel the relay cannot rewrite field by
    field, so it is default-deny: a listed (extension, evtype) passes, everything
    else -- an unlisted evtype, an unknown extension -- is withheld."""
    conn = make_connection()
    conn.extension_opcodes = {131: "XInputExtension"}
    # the XInput2 input events a toolkit needs on its own windows pass
    for evtype in (2, 3, 4, 5, 6):                      # Key/Button/Motion
        assert conn.patch_generic_event(*generic_event(131, evtype)) is None, evtype
    # the crossing and focus events carry the global position and modifiers and
    # cannot be scrubbed as an XGE, so they are dropped
    for evtype in (7, 8, 9, 10):                        # Enter/Leave/Focus
        assert conn.patch_generic_event(*generic_event(131, evtype)) \
            is conn.DROP_EVENT, evtype
    # the raw taps are dropped
    assert conn.patch_generic_event(*generic_event(131, 13)) is conn.DROP_EVENT
    # an XGE from an extension with no allowlist entry is dropped
    assert conn.patch_generic_event(*generic_event(200, 1)) is conn.DROP_EVENT
    # dry-run enforces nothing: the event passes, but the log still names it
    dry = make_connection(enforce=False)
    dry.extension_opcodes = {131: "XInputExtension"}
    assert dry.patch_generic_event(*generic_event(131, 7)) is None


def test_xinput_focus_and_warp_are_scoped():
    conn = make_connection()
    conn.extension_opcodes = {131: "XInputExtension"}
    assert conn.judge(131, 49, struct.pack(LE + "I", ROOT))[0] == "silent"
    assert conn.judge(131, 49, struct.pack(LE + "I", OWN))[0] == "allow"
    assert conn.judge(131, 41,
                      struct.pack(LE + "II", 0, FOREIGN))[0] == "silent"


def test_render_picture_of_foreign_drawable_is_refused():
    conn = make_connection()
    conn.extension_opcodes = {139: "RENDER"}
    pid = OWN | 0x5
    assert conn.judge(139, 4,
                      struct.pack(LE + "IIII", pid, ROOT, 0x29, 0))[0] == "silent"
    assert conn.judge(139, 4,
                      struct.pack(LE + "IIII", pid, OWN, 0x29, 0))[0] == "allow"


# -- polling keyloggers and trackers ----------------------------------------

def test_querykeymap_reports_no_keys_down():
    conn = make_connection()
    verdict, _ = conn.judge(44, 0, b"")
    assert callable(verdict), "QueryKeymap must not pass through unfiltered"
    reply = verdict(7)
    assert reply[0] == 1 and len(reply) == 40, "a valid QueryKeymap reply"
    assert reply[8:] == b"\0" * 32, "no key may be reported down"


def test_querypointer_mask_is_scrubbed():
    # QueryPointer now takes the "pointer" strategy: the reply's button/modifier
    # mask is always blanked, and the global position is bounded to the client's
    # own window (see test_query_pointer_is_bounded_to_the_clients_own_window).
    conn = make_connection()
    verdict, _ = conn.judge(38, 0, struct.pack(LE + "I", OWN))
    assert isinstance(verdict, tuple) and verdict[0] == "pointer", \
        "QueryPointer takes the pointer-bounding strategy"
    assert verdict[1][1] == "core", "the core reply layout"
    # the input-state mask is still blanked, whatever the position decision
    head = struct.pack(LE + "BBH", 1, 1, 0) + b"\0" * 5
    body = bytearray(24)
    struct.pack_into(LE + "H", body, 16, 0xFFFF)     # mask at reply offset 24
    scrubbed = conn.bound_pointer_reply(head, bytes(body), None, "core")
    assert struct.unpack_from(LE + "H", scrubbed, 24)[0] == 0, "mask blanked"
    # the XInput twin takes the same strategy, xi layout
    conn.extension_opcodes = {131: "XInputExtension"}
    xiverdict, _ = conn.judge(131, 40, struct.pack(LE + "IHH", OWN, 0, 0))
    assert isinstance(xiverdict, tuple) and xiverdict[0] == "pointer"
    assert xiverdict[1][1] == "xi"


def test_scrub_blanks_only_the_named_reply_bytes():
    conn = make_connection()
    reply = bytes(range(40))
    scrubbed = conn.scrub_reply(reply[:32], reply[32:], [(24, 2)])
    assert scrubbed[24:26] == b"\0\0", "the mask bytes are zeroed"
    assert scrubbed[:24] == reply[:24], "everything before is untouched"
    assert scrubbed[26:] == reply[26:], "everything after is untouched"


def test_default_deny_blocks_the_unlisted():
    conn = make_connection()
    # GetMotionEvents (39): not on the safe list and no rule -> blocked
    assert conn.judge(39, 0, struct.pack(LE + "I", OWN))[0] == "block"
    # a drawing primitive on the safe list -> allowed
    assert conn.judge(70, 0, b"\0" * 8)[0] == "allow"          # PolyFillRectangle
    # an unknown extension opcode (not denied, inspected, or allowed) -> blocked
    assert conn.judge(200, 0, b"")[0] == "block"


def _value_list(mask, marked_bit, marked_value, other=0):
    """The value list a client sends for `mask`: one word per set bit, in
    ascending bit order, with `marked_bit`'s word set to `marked_value`."""
    values = b""
    for bit in sorted(1 << n for n in range(32) if mask & (1 << n)):
        values += struct.pack(LE + "I",
                              marked_value if bit == marked_bit else other)
    return values


def test_a_value_lists_gated_word_is_found_wherever_the_mask_puts_it():
    """The gated value must be read from where the *client* put it, for every
    shape of mask.

    A value list carries one word per set bit, in ascending bit order, so the
    offset of the word a rule cares about depends on which other bits are set.
    `_value_offset` computes that by counting bits, and the eighth pass checked
    it by reading the code.  This checks it by construction: for every subset
    of the mask bits, the fullscreen gate must fire when override-redirect is
    the dangerous value and stay quiet when it is not -- so the rule is reading
    that word and no other, wherever it lands.  A truncated list, which the
    rule cannot read at all, must refuse rather than skip.
    """
    conn = fs_connection()
    attributes = [1 << n for n in range(15)]          # CWBackPixmap .. CWCursor
    override = xfilter.CW_OVERRIDE_REDIRECT
    misread = []
    for extra in range(1 << len(attributes)):
        mask = override
        for index, bit in enumerate(attributes):
            if extra & (1 << index) and bit != override:
                mask |= bit
        if bin(mask).count("1") > 6:                  # a sample, not 32k bodies
            continue

        # ChangeWindowAttributes on a fullscreen-sized own window
        conn.profile.note_window(OWN, ROOT, FS_W, FS_H, False)
        request = struct.pack(LE + "II", OWN, mask)
        on = request + _value_list(mask, override, 1, other=0xFFFFFFFF)
        off = request + _value_list(mask, override, 0, other=0xFFFFFFFF)
        if not isinstance(conn.judge(2, 0, on)[0], tuple):
            misread.append("mask 0x%x: override-redirect not seen" % mask)
        if conn.judge(2, 0, off)[0] != "allow":
            misread.append("mask 0x%x: something else read as override" % mask)
        # the list cut short of that word: unreadable, so refused
        cut = request + _value_list(mask, override, 1)[:-4]
        if conn.judge(2, 0, cut)[0] == "allow":
            misread.append("mask 0x%x: truncated list allowed" % mask)
    assert not misread, "the value-list offset is wrong:\n    " \
        + "\n    ".join(misread[:12])


def test_configure_windows_gated_words_are_found_the_same_way():
    """The same question for ConfigureWindow, whose mask is 16-bit and whose
    gated words are the size a window is being resized to, and the sibling it
    is being stacked against."""
    conn = fs_connection()
    conn.profile.note_window(OWN, ROOT, SMALL_W, SMALL_H, True)   # override-redirect
    bits = [1 << n for n in range(7)]                # CWX .. CWStackMode
    width, height, sibling = xfilter.CONFIGURE_WIDTH, xfilter.CONFIGURE_HEIGHT, \
        xfilter.CW_SIBLING
    wrong = []
    for extra in range(1 << len(bits)):
        mask = width | height
        for index, bit in enumerate(bits):
            if extra & (1 << index):
                mask |= bit
        values = b""
        for bit in sorted(bits):
            if not mask & bit:
                continue
            if bit == width:
                values += struct.pack(LE + "I", FS_W)
            elif bit == height:
                values += struct.pack(LE + "I", FS_H)
            elif bit == sibling:
                values += struct.pack(LE + "I", OWN)
            else:
                values += struct.pack(LE + "I", 7)
        request = struct.pack(LE + "IHxx", OWN, mask) + values
        verdict = conn.judge(12, 0, request)[0]
        if not (isinstance(verdict, tuple) and verdict[0] == "fullscreen"):
            wrong.append("mask 0x%x: the resize to fullscreen was missed" % mask)
        if mask & sibling:
            foreign = request[:8 + 4 * bin(mask & (sibling - 1)).count("1")] \
                + struct.pack(LE + "I", FOREIGN) \
                + request[12 + 4 * bin(mask & (sibling - 1)).count("1"):]
            if conn.judge(12, 0, foreign)[0] != "silent":
                wrong.append("mask 0x%x: the foreign sibling was missed" % mask)
    assert not wrong, "ConfigureWindow reads the wrong word:\n    " \
        + "\n    ".join(wrong[:12])


def test_no_substitution_leaks_a_field_it_meant_to_blank():
    """A reply shorter than the range a rule blanks must not keep the field.

    The scrubbers clamp their ranges to the reply they were given, which is
    right -- they must not read past it -- but clamping is only safe if a short
    reply cannot then carry the very bytes the rule exists to remove.  The
    question is the reply-side twin of the truncation sweep above, and it is
    asked of every substitution the policy performs, at every length.
    """
    conn = rooted_connection()
    leaked = []

    def blanked(produce, offsets, length):
        """produce() a scrubbed reply of `length` bytes; True if every one of
        `offsets` is either gone or zero."""
        buffer = bytearray(64)
        buffer[0] = 1
        for offset in offsets:
            struct.pack_into(LE + "I", buffer, offset, FOREIGN)
        head, body = bytes(buffer[:32]), bytes(buffer[32:length or 32])
        out = produce(head[:length] if length < 32 else head, body)
        for offset in offsets:
            if offset + 4 <= len(out) and \
                    struct.unpack_from(LE + "I", out, offset)[0] not in (0, 0xFFFFFFFF):
                return False
        return True

    for length in range(0, 64, 4):
        # the modifier/lock state scrubs, the focus and selection-owner
        # stand-ins, and the pointer bound, each against a reply cut to `length`
        if not blanked(lambda h, b: conn.scrub_reply(h, b, [(8, 18)]),
                       [8, 12, 16, 20], length):
            leaked.append("scrub_reply kept state at %d bytes" % length)
        if not blanked(lambda h, b: conn.scrub_foreign_windows(h, b, [8], 0),
                       [8], length):
            leaked.append("scrub_foreign_windows kept a window at %d bytes"
                          % length)
        if not blanked(
                lambda h, b: conn.scrub_foreign_windows(
                    h, b, [8], xfilter.SELECTION_OWNER_STANDIN), [8], length):
            leaked.append("the selection stand-in kept an owner at %d bytes"
                          % length)
    assert not leaked, "a substitution left what it meant to remove:\n    " \
        + "\n    ".join(leaked[:8])


def _judge_like_forward(conn, opcode, minor, body):
    """judge(), with the same guard forward() puts around it: a request the
    policy cannot parse is blocked rather than passed."""
    try:
        return conn.judge(opcode, minor, body)[0]
    except (struct.error, IndexError, UnicodeDecodeError):
        return "block"


def _gated_requests():
    """Every (opcode, minor, offsets) the policy gates on a foreign resource,
    read out of the policy's own tables so this cannot fall behind them."""
    for opcode, offsets in xfilter.FOREIGN_RESOURCE_REQUESTS.items():
        yield "core", opcode, 0, offsets
    for opcode, offsets in xfilter.SCREEN_REFERENCE_REQUESTS.items():
        yield "core", opcode, 0, offsets
    for opcode, offsets in xfilter.SCREEN_REFERENCE_REPLIES.items():
        yield "core", opcode, 0, offsets
    for opcode, offsets in xfilter.CURSOR_SOURCE_REQUESTS.items():
        yield "core", opcode, 0, offsets
    for opcode in xfilter.WINDOW_WRITE_REQUESTS:
        yield "core", opcode, 0, (0,)
    for opcode in (3, 14, 15, 21, 73):        # attributes, geometry, tree, image
        yield "core", opcode, 0, (0,)
    for minor, offsets in xfilter.XFIXES_FOREIGN.items():
        yield "XFIXES", 142, minor, offsets
    for minor, offsets in xfilter.RENDER_FOREIGN.items():
        yield "RENDER", 139, minor, offsets
    for minor, offsets in xfilter.SYNC_FOREIGN.items():
        yield "SYNC", 134, minor, offsets
    for minor in xfilter.SHAPE_WINDOW_WRITES:
        yield "SHAPE", 141, minor, (4,)
    for minor in xfilter.XI_FOREIGN_WINDOW_READS:
        yield "XInputExtension", 131, minor, (0,)


def test_no_gate_falls_open_on_a_body_too_short_to_read():
    """A rule that cannot read its field must refuse, not shrug.

    This is the shape the audit has found by hand twice -- `if len(body) >=
    offset + 4` and then a fall-through to allow, in XKB's GetDeviceInfo and in
    the foreign-window event mask -- so it is worth asking the question of every
    gated request at once rather than one at a time.  The bodies come from the
    policy's own tables, so a rule added later is swept too.
    """
    conn = rooted_connection()
    conn.extension_opcodes = {142: "XFIXES", 139: "RENDER", 134: "SYNC",
                              141: "SHAPE", 131: "XInputExtension"}
    escaped = []
    for label, opcode, minor, offsets in _gated_requests():
        full = max(offsets) + 4
        body = bytearray(full + 16)
        for offset in offsets:                # every gated field names a stranger
            struct.pack_into(LE + "I", body, offset, FOREIGN)
        if _judge_like_forward(conn, opcode, minor, bytes(body)) == "allow":
            escaped.append("%s:%s/%s naming a foreign resource"
                           % (label, opcode, minor))
            continue
        for length in range(0, len(body), 4):        # ...and every truncation
            if _judge_like_forward(conn, opcode, minor,
                                   bytes(body[:length])) == "allow":
                escaped.append("%s:%s/%s truncated to %d bytes"
                               % (label, opcode, minor, length))
    assert not escaped, "a gate let a foreign request through:\n    " \
        + "\n    ".join(escaped)


def test_a_departed_connections_range_stops_being_ours():
    # The X server hands each client a resource-id range from a fixed table and
    # reuses a range once its client disconnects.  The profile kept every range
    # it had ever seen, so after a filtered connection ended, the trusted
    # application that inherited its range was treated as ours -- windows
    # readable, capturable, writable.  Found by the attack suite: a direct
    # client was given 0xc00000, a base a filtered connection had held earlier
    # in the same run, and GetImage on its window returned 4096 bytes.
    profile = xfilter.PolicyProfile()
    profile.note_range(BASE, MASK)
    assert profile.is_foreign(BASE | 0x11) is False, "ours while it is ours"

    profile.forget_range(BASE, MASK)
    assert profile.is_foreign(BASE | 0x11) is True, \
        "and a stranger's the moment the server may hand it to a stranger"

    # an application's *other* connections keep theirs: the ranges are counted,
    # not shared, so one closing does not disown the rest
    profile.note_range(BASE, MASK)
    profile.note_range(BASE, MASK)
    profile.forget_range(BASE, MASK)
    assert profile.is_foreign(BASE | 0x11) is False, \
        "a sibling connection still holds this range"
    profile.forget_range(BASE, MASK)
    assert profile.is_foreign(BASE | 0x11) is True


def test_a_denied_extension_answers_instead_of_hanging():
    # A hidden extension is reported absent, so anything sent to its opcode is
    # a guess at a number that is stable and guessable.  Dropping it silently
    # left a reply-bearing request -- Composite's QueryVersion, say -- waiting
    # for a reply that never came; found under Xephyr, which has Composite
    # where Xvfb does not.  BadRequest is also what a server without the
    # extension would answer, so the opcode now agrees with QueryExtension.
    conn = make_connection(enforce=True)
    conn.denied_opcodes = {142}
    answer, reason = conn.judge(142, 0, b"")
    assert callable(answer) and reason == "extension denied"
    error = answer(9)
    assert error[0] == 0, "an error, not a reply"
    assert error[1] == xfilter.BAD_REQUEST, "the code a server with no such "\
        "extension would send"
    assert struct.unpack_from(LE + "H", error, 2)[0] == 9, "sequence consumed"
    # an X error is type, code, sequence, bad value, minor (2 bytes), major
    assert struct.unpack_from(LE + "H", error, 8)[0] == 0, "the minor opcode"
    assert error[10] == 142, "and the major, so the client knows what failed"


def test_screensaver_control_is_refused():
    conn = make_connection()
    assert conn.judge(107, 0, b"")[0] == "silent", "SetScreenSaver refused"
    assert conn.judge(115, 0, b"")[0] == "silent", "ForceScreenSaver refused"


def test_xinput1_device_grabs_are_refused():
    conn = make_connection()
    conn.extension_opcodes = {131: "XInputExtension"}
    root = struct.pack(LE + "I", ROOT)
    assert callable(conn.judge(131, 13, root)[0]), "XI1 GrabDevice refused"
    assert conn.judge(131, 15, root)[0] == "silent", "XI1 GrabDeviceKey refused"
    assert conn.judge(131, 17, root)[0] == "silent", "XI1 GrabDeviceButton refused"
    assert conn.judge(131, 15, struct.pack(LE + "I", OWN))[0] == "allow"


# -- session-wide input and server state ------------------------------------

def test_server_grab_and_input_state_are_refused():
    conn = make_connection()
    assert conn.judge(36, 0, b"")[0] == "silent", "GrabServer must be refused"
    assert conn.judge(37, 0, b"")[0] == "silent", "UngrabServer must be refused"
    assert conn.judge(100, 0, b"")[0] == "silent", "keyboard remap refused"
    assert callable(conn.judge(116, 0, b"")[0]), "pointer remap answered"
    assert callable(conn.judge(118, 0, b"")[0]), "modifier remap answered"
    # focus and warp are scoped to the client's own windows
    assert conn.judge(42, 0, struct.pack(LE + "I", FOREIGN))[0] == "silent"
    assert conn.judge(42, 0, struct.pack(LE + "I", OWN))[0] == "allow"
    assert conn.judge(42, 0, struct.pack(LE + "I", 1))[0] == "allow"   # PointerRoot
    assert conn.judge(41, 0, struct.pack(LE + "II", 0, FOREIGN))[0] == "silent"
    assert conn.judge(41, 0, struct.pack(LE + "II", 0, OWN))[0] == "allow"


# -- the SelectionNotify patch, on the refusal path -------------------------

def test_selection_notify_is_patched_when_owner_is_absent():
    conn = make_connection()
    sent = []
    conn.server = type("S", (), {"sendall": lambda _s, d: sent.append(d)})()
    conn.forward(24, 0, struct.pack(LE + "BBH", 24, 0, 6),
                 convert_selection(OWN, 100, target=31, prop=200))
    event = bytearray(32)
    event[0] = 31                                       # SelectionNotify
    struct.pack_into(LE + "I", event, 8, OWN)           # requestor
    struct.pack_into(LE + "I", event, 12, xfilter.UNOWNED_ATOM)  # server's atom
    struct.pack_into(LE + "I", event, 16, 31)           # target, preserved
    struct.pack_into(LE + "I", event, 20, 0)            # property None: no owner
    patched = conn.patch_event(bytes(event))
    assert patched is not None, "the refusal path must still be patched"
    assert struct.unpack_from(LE + "I", patched, 12)[0] == 100, \
        "the client must see a refusal for CLIPBOARD, not MIN_SPACE"
    assert struct.unpack_from(LE + "I", patched, 20)[0] == 0


# -- the root window is read at the right offsets ---------------------------

def test_find_root_reads_the_real_root():
    conn = make_connection()
    vendor = b"Test"
    nformats = 1
    body = bytearray(32)
    struct.pack_into(LE + "H", body, 16, len(vendor))
    body[21] = nformats
    body += vendor + b"\0" * core.pad4(len(vendor))
    body += b"\0" * (8 * nformats)
    body += struct.pack(LE + "I", 0x2A) + b"\0" * 100   # SCREEN: root first
    conn.root = 0
    conn.find_root(bytes(body))
    assert conn.root == 0x2A, "find_root must not land eight bytes late"


def setup_reply(root=0x2A, visual=0x21, depth=24):
    """A setup reply body with one screen, shaped as find_root reads it."""
    vendor, nformats = b"Test", 1
    body = bytearray(32)
    struct.pack_into(LE + "H", body, 16, len(vendor))
    body[20] = 1                                    # one screen
    body[21] = nformats
    body += vendor + b"\0" * core.pad4(len(vendor))
    body += b"\0" * (8 * nformats)
    screen = bytearray(40)                          # SCREEN is 40 bytes
    struct.pack_into(LE + "I", screen, 0, root)     # root window
    struct.pack_into(LE + "I", screen, 32, visual)  # root visual id
    screen[38] = depth                              # root depth
    screen[39] = 0                                  # no allowed-depths to walk
    return bytes(body + screen)


def test_blank_attributes_name_a_visual_the_client_can_resolve():
    """A blank answer must still be a coherent one.

    Xlib turns the reply's visual *id* into a Visual* through _XVIDtoVisual,
    which answers NULL for an id the screen does not list -- and 0 is never
    listed -- while still reporting success.  A client that then reads the
    pointer (XVisualIDFromVisual) dereferences NULL and dies, so reporting 0
    here crashes the application we meant to merely tell nothing to.
    """
    conn = make_connection()
    conn.find_root(setup_reply(root=0x2A, visual=0x21))
    assert conn.root_visual == 0x21, "the root visual is at SCREEN offset 32"

    reply = conn._blank_attributes(7)
    assert len(reply) == 44, "GetWindowAttributes replies are 44 bytes"
    visual, window_class = struct.unpack_from(LE + "IH", reply, 8)
    assert visual == conn.root_visual, \
        "a foreign window must be described on a visual that resolves"
    assert visual != 0, "id 0 resolves to NULL and takes the client down"
    assert window_class == 1, "InputOutput, matching the visual we named"


# -- the operations sentinel (the new statistic and its alert) --------------

def test_first_seen_records_each_operation_once():
    profile = xfilter.PolicyProfile()
    key = ("core:GetImage", True)
    assert profile.note_first_seen(key, "app", "peer", True, None) is True
    assert profile.note_first_seen(key, "app", "peer", True, None) is False, \
        "a repeat is not new"
    assert profile.first_seen[key] == ("app", "peer", True, None)


def test_sentinel_logs_each_operation_once():
    conn = make_connection()
    conn.sentinel(73, 2, "allow", None)               # GetImage
    conn.sentinel(73, 2, "allow", None)               # same again -> deduped
    conn.sentinel(38, 0, ("scrub", [(24, 2)]), "mask")  # scrub counts as allowed
    conn.sentinel(39, 0, "block", "not on the allowlist")  # GetMotionEvents
    assert conn.seen == {(73, True), (38, True), (39, False)}, \
        "the hot path dedups on a cheap key"
    assert conn.profile.first_seen[("core:GetImage", True)][2] is True
    assert conn.profile.first_seen[("core:QueryPointer", True)][2] is True, \
        "scrub reads as allowed"
    assert conn.profile.first_seen[("core:GetMotionEvents", False)][2] is False
    assert len(conn.profile.first_seen) == 3


def test_an_allow_does_not_hide_a_later_block_of_the_same_request():
    """The log keys on the verdict, not just the request name.

    Nearly every windowed request is allowed on the client's own window and
    refused on a foreign one.  Keying the log on the name alone means the
    first outcome is the only one ever reported -- so an over-block sits
    invisible behind an earlier allow of the same request, which is exactly
    the event the log exists to surface.
    """
    conn = make_connection()
    conn.sentinel(20, 0, "allow", None)                    # GetProperty, own
    conn.sentinel(20, 0, "block", "foreign property")      # ... then foreign
    assert conn.profile.first_seen[("core:GetProperty", True)][2] is True
    assert ("core:GetProperty", False) in conn.profile.first_seen, \
        "the blocked outcome must survive the earlier allow"
    assert conn.profile.first_seen[("core:GetProperty", False)][3] \
        == "foreign property", "and it must carry the rule that refused it"
    # a third of each is still deduped
    conn.sentinel(20, 0, "allow", None)
    conn.sentinel(20, 0, "block", "foreign property")
    assert len(conn.profile.first_seen) == 2


def test_releasing_a_grab_is_allowed_wherever_taking_one_was():
    """Allowing a grab and refusing its release is worse than either.

    The grab then lasts until the client exits, and nothing else in the
    session sees a key or a click in the meantime.
    """
    conn = make_connection()
    conn.root = ROOT
    conn.roots = {ROOT}
    # UngrabPointer / UngrabKeyboard carry a timestamp and no window at all
    assert conn.judge(27, 0, struct.pack(LE + "I", 0))[0] == "allow", \
        "UngrabPointer names no window to gate"
    assert conn.judge(32, 0, struct.pack(LE + "I", 0))[0] == "allow", \
        "UngrabKeyboard names no window to gate"
    # UngrabButton / UngrabKey name the grab window, and follow the grab
    for take, release in ((28, 29), (33, 34)):
        own = struct.pack(LE + "IHH", OWN, 0, 0)
        foreign = struct.pack(LE + "IHH", FOREIGN, 0, 0)
        assert conn.judge(take, 0, own)[0] == "allow"
        assert conn.judge(release, 0, own)[0] == "allow", \
            "a client must be able to undo a grab it was allowed to take"
        assert conn.judge(take, 0, foreign)[0] == "silent"
        assert conn.judge(release, 0, foreign)[0] == "silent"


# -- BIG-REQUESTS framing -------------------------------------------

def _bigreq_connection():
    profile = xfilter.PolicyProfile()
    profile.note_range(BASE, MASK)
    client, peer = socket.socketpair()
    conn = xfilter.PolicyConnection(client, None, None, None, profile,
                                    enforce=True)
    conn.endian = LE
    conn.alert_new = False
    conn.max_request_units = 65535
    sent = []
    conn.server = type("S", (), {"sendall": lambda _s, d: sent.append(d)})()
    return conn, peer, sent


def test_zero_length_request_before_bigreqenable_drops_the_link():
    conn, peer, sent = _bigreq_connection()
    getimage = (struct.pack(LE + "BBH", 73, 2, 5)
                + struct.pack(LE + "IhhHHI", FOREIGN, 0, 0, 8, 8, 0xFFFFFFFF))
    # a zero-length header claims the BIG-REQUESTS form the client never enabled
    peer.sendall(struct.pack(LE + "BBH", 127, 0, 0)
                 + struct.pack(LE + "I", 2 + len(getimage) // 4) + getimage)
    peer.close()
    conn.client_to_server()
    assert sent == [], "an unframeable header must forward nothing"


def test_zero_length_request_is_allowed_once_bigreq_is_enabled():
    conn, peer, sent = _bigreq_connection()
    conn.big_requests_enabled = True
    peer.sendall(struct.pack(LE + "BBH", 127, 0, 0)   # NoOperation, big form
                 + struct.pack(LE + "I", 2))          # 2 units = header only
    peer.close()
    conn.client_to_server()
    assert sent, "an enabled zero-length request should still be relayed"


def test_oversized_request_is_dropped():
    conn, peer, sent = _bigreq_connection()
    conn.big_requests_enabled = True
    conn.max_request_units = 16
    peer.sendall(struct.pack(LE + "BBH", 127, 0, 0)
                 + struct.pack(LE + "I", 1 << 20))    # a million units
    peer.close()
    conn.client_to_server()
    assert sent == [], "a request past the server's maximum must be dropped"


# -- the write direction ---------------------------------------------------

def window_write(window, extra=0):
    return struct.pack(LE + "II", window, extra)


def test_foreign_windows_cannot_be_modified():
    conn = make_connection()
    for name in ("DestroyWindow", "DestroySubwindows", "ChangeSaveSet",
                 "ReparentWindow", "MapWindow", "MapSubwindows",
                 "UnmapWindow", "UnmapSubwindows", "ConfigureWindow",
                 "CirculateWindow"):
        opcode = xfilter._OPCODE[name]
        assert conn.judge(opcode, 0, window_write(FOREIGN))[0] == "silent", name
        assert conn.judge(opcode, 0, window_write(OWN))[0] == "allow", name


def test_reparent_may_adopt_a_foreign_parent():
    # putting your own window under a foreign parent is XEmbed and system
    # trays; putting a foreign window under yours captures its input
    conn = make_connection()
    assert conn.judge(7, 0, window_write(OWN, FOREIGN))[0] == "allow"
    assert conn.judge(7, 0, window_write(FOREIGN, OWN))[0] == "silent"


def test_configure_window_checks_the_sibling():
    conn = make_connection()
    mask = xfilter.CW_SIBLING | 0x1 | 0x2          # x, y, then the sibling
    def configure(sibling):
        return struct.pack(LE + "IHxxIII", OWN, mask, 0, 0, sibling)
    assert conn.judge(12, 0, configure(OWN))[0] == "allow"
    assert conn.judge(12, 0, configure(FOREIGN))[0] == "silent"


def set_selection_owner(owner, selection):
    return struct.pack(LE + "III", owner, selection, 0)


def test_taking_a_selection_is_gated_like_reading_one():
    conn = make_connection()                       # gate deny
    assert conn.judge(22, 0, set_selection_owner(OWN, 100))[0] == "silent"
    assert conn.judge(22, 0, set_selection_owner(OWN, 105))[0] == "allow", \
        "a selection of the application's own is its business"
    assert conn.judge(22, 0, set_selection_owner(0, 100))[0] == "allow", \
        "releasing what you hold is not taking anything"
    assert make_connection("allow").judge(
        22, 0, set_selection_owner(OWN, 100))[0] == "allow"
    asking = make_connection("ask")
    asking.gate = object()
    assert asking.judge(22, 0, set_selection_owner(OWN, 100))[0] == "ask-owner"


def test_a_read_grant_is_not_an_ownership_grant():
    gate = xfilter.Gate(timeout=0, remember=300)
    gate.decisions[(1, "CLIPBOARD", "read")] = (True, time.time() + 300)
    assert gate.decide(1, "app", "CLIPBOARD", "STRING", "peer") is True
    asked = []

    def answer_once():
        request = gate.requests.get(timeout=2)
        asked.append(request[4])
        request[5]["allow"] = False
        request[6].set()

    threading.Thread(target=answer_once, daemon=True).start()
    assert gate.decide(1, "app", "CLIPBOARD", "ownership", "peer",
                       action="own") is False
    assert asked == ["own"], "becoming the clipboard is asked for separately"


def ewmh_message(destination, message_atom, target):
    event = bytearray(32)
    event[0] = 33                                  # ClientMessage
    struct.pack_into(LE + "I", event, 4, target)   # the event's window field
    struct.pack_into(LE + "I", event, 8, message_atom)
    return struct.pack(LE + "II", destination, 0) + bytes(event)


def test_ewmh_message_cannot_name_a_foreign_window():
    conn = make_connection()
    conn.profile.note_atom(110, "_NET_CLOSE_WINDOW")
    assert conn.judge(25, 0, ewmh_message(ROOT, 110, OWN))[0] == "allow", \
        "closing your own window through the window manager is ordinary"
    assert conn.judge(25, 0, ewmh_message(ROOT, 110, FOREIGN))[0] == "silent"
    # _NET_WM_STATE *does* act on the window named in the message (fullscreen,
    # maximize, hide, ...), so on a foreign window it is refused.  An own-window
    # _NET_WM_STATE that does not name fullscreen is still ordinary.
    assert conn.judge(25, 0, ewmh_message(ROOT, 104, FOREIGN))[0] == "silent"
    assert conn.judge(25, 0, ewmh_message(ROOT, 104, OWN))[0] == "allow"


def test_ewmh_window_manipulation_messages_check_the_target():
    """Every EWMH/ICCCM message that acts on the window named in its own field
    is refused on a foreign window -- the tenth-pass gap.  WM_CHANGE_STATE was
    demonstrated live (a filtered client iconified a trusted window); the rest
    act on event.window by the same spec and reach the window manager the same
    way."""
    conn = make_connection()
    for atom, name in ((120, "WM_CHANGE_STATE"), (121, "_NET_WM_MOVERESIZE"),
                       (122, "_NET_WM_DESKTOP"),
                       (123, "_NET_WM_FULLSCREEN_MONITORS")):
        conn.profile.note_atom(atom, name)
        assert conn.judge(25, 0, ewmh_message(ROOT, atom, FOREIGN))[0] \
            == "silent", name
        assert conn.judge(25, 0, ewmh_message(ROOT, atom, OWN))[0] \
            == "allow", name


def test_crossing_events_on_a_foreign_window_are_refused():
    """Selecting EnterWindow/LeaveWindow on the root -- a foreign window -- is
    refused: a crossing event carries the global pointer position and the live
    modifier state, so it is the QueryPointer trace and the XkbGetState poll in
    one, both of which the ninth pass had already closed on their own routes.
    On a window the client owns the same selection is ordinary hover handling."""
    conn = make_connection()
    mask = xfilter.CW_EVENT_MASK
    def cwa(window, bits):
        return struct.pack(LE + "III", window, mask, bits)
    crossing = 0x10 | 0x20                              # Enter|LeaveWindow
    assert conn.judge(2, 0, cwa(ROOT, crossing))[0] == "silent"
    assert conn.judge(2, 0, cwa(FOREIGN, 0x10))[0] == "silent"
    assert conn.judge(2, 0, cwa(OWN, crossing))[0] == "allow"
    # the one event still allowed on a foreign window (PropertyChange, for
    # XSETTINGS/_NET_*) still passes -- the allowlist is not empty
    assert conn.judge(2, 0, cwa(ROOT, 0x400000))[0] == "allow"  # PropertyChange


def test_xinput_crossing_and_focus_selection_on_root_is_refused():
    """The XInput2 twins: XI_Enter/Leave/FocusIn/FocusOut also carry the global
    position and modifiers, and arrive as GenericEvents the relay cannot filter,
    so they are refused at selection on a foreign window.  The device-plumbing
    events a toolkit legitimately selects on the root stay allowed."""
    conn = make_connection()
    conn.extension_opcodes = {131: "XInputExtension"}
    for bit in (7, 8, 9, 10):                           # Enter, Leave, Focus*
        assert conn.judge(131, 46, xi_select_events(ROOT, 1 << bit))[0] \
            == "silent", bit
        assert conn.judge(131, 46, xi_select_events(OWN, 1 << bit))[0] \
            == "allow", bit
    for bit in (1, 11, 12):                             # DeviceChanged/Hierarchy/Property
        assert conn.judge(131, 46, xi_select_events(ROOT, 1 << bit))[0] \
            == "allow", bit


# -- the extension write surface -------------------------------------------

def test_xkb_reads_pass_and_writes_are_refused():
    conn = make_connection()
    conn.extension_opcodes = {135: "XKEYBOARD"}
    assert conn.judge(135, 0, b"")[0] == "allow", \
        "UseExtension is the version handshake every client opens with"
    assert conn.judge(135, 8, b"")[0] == "allow"       # XkbGetMap
    assert conn.judge(135, 4, b"")[0][0] == "scrub", \
        "XkbGetState is a modifier poll; its state fields are blanked (EV-6)"
    assert conn.judge(135, 21, b"")[0] == "allow", \
        "detectable auto-repeat is per-connection and every toolkit wants it"
    assert conn.judge(135, 9, b"")[0] == "silent"      # XkbSetMap
    assert conn.judge(135, 7, b"")[0] == "silent"      # XkbSetControls
    assert conn.judge(135, 5, b"")[0] == "silent"      # XkbLatchLockState
    assert conn.judge(135, 18, b"")[0] == "silent"     # XkbSetNames
    # GetKbdByName loads a keymap despite the name, and expects a reply: an
    # unanswered refusal would leave the client waiting for one forever
    assert callable(conn.judge(135, 23, b"")[0])


def test_keyboard_lock_state_is_blanked_by_all_four_of_its_names():
    # Eleventh pass.  The ninth blanked the modifier/group state (XkbGetState);
    # the *lock* state -- Caps, Num, Scroll, and whatever else the layout binds
    # an indicator to -- stayed readable through three XKB requests and one
    # core one, each measured answering 0x1 through the proxy with Caps Lock
    # engaged.  Every transition in it is a key the user pressed.
    conn = make_connection()
    conn.extension_opcodes = {135: "XKEYBOARD"}

    verdict, _ = conn.judge(103, 0, b"")               # GetKeyboardControl
    assert verdict == ("scrub", [(8, 4)]), \
        "the core LED mask is at offset 8; the rest of the reply is config"

    verdict, _ = conn.judge(135, 12, b"")              # XkbGetIndicatorState
    assert verdict == ("scrub", [(8, 4)])

    verdict, _ = conn.judge(135, 15, b"")              # XkbGetNamedIndicator
    assert verdict == ("scrub", [(13, 1)]), \
        "`on` is the live bit; `found` and the map are configuration"

    # XkbGetDeviceInfo asks for several facets at once, so the indicator ones
    # are stripped from the request rather than the whole request refused.
    def device_info(wanted):
        return struct.pack(LE + "HHBBBBHH", 0x0100, wanted, 0, 0, 0, 0, 0, 0)

    verdict, _ = conn.judge(135, 24, device_info(0x0010))   # IndicatorState
    assert isinstance(verdict, tuple) and verdict[0] == "rewrite"
    assert struct.unpack_from(LE + "H", verdict[1], 2)[0] == 0, \
        "the indicator facets are cleared out of the forwarded request"
    for wanted in (0x0004, 0x0008):        # IndicatorNames, IndicatorMaps
        assert conn.judge(135, 24, device_info(wanted))[0][0] == "rewrite", \
            "the state rides along with the names and the maps"
    assert conn.judge(135, 24, device_info(0x0002))[0] == "allow", \
        "asking for button actions alone is untouched"
    assert callable(conn.judge(135, 24, b"\0\0")[0]), \
        "a body too short to carry the facet mask is refused, not passed"


def test_xinput_feedback_leds_are_blanked():
    # Eleventh pass, the sixth name for the lock state: the XInput1 keyboard
    # feedback record carries led_mask and led_values.  They sit in a
    # variable-length list, so the reply is walked rather than scrubbed at a
    # fixed offset -- and only the keyboard class is touched.
    conn = make_connection()
    conn.extension_opcodes = {131: "XInputExtension"}
    assert conn.judge(131, 22, struct.pack(LE + "BBBB", 3, 0, 0, 0))[0] \
        == "feedback"

    def feedback_reply():
        head = bytearray(32)
        head[0] = 1
        struct.pack_into(LE + "H", head, 8, 2)         # two feedbacks
        kbd = bytearray(20)                            # class 0, the keyboard
        struct.pack_into(LE + "BBH", kbd, 0, 0, 7, 20)
        struct.pack_into(LE + "HH", kbd, 4, 400, 100)  # pitch, duration
        struct.pack_into(LE + "II", kbd, 8, 0x1, 0x1)  # led_mask, led_values
        ptr = bytearray(12)                            # class 2, the pointer
        struct.pack_into(LE + "BBH", ptr, 0, 2, 9, 12)
        struct.pack_into(LE + "II", ptr, 4, 0x2, 0x2)  # accel: not LED state
        return bytes(head), bytes(kbd + ptr)

    head, body = feedback_reply()
    blanked = conn.blank_feedback_leds(head, body)
    assert struct.unpack_from(LE + "II", blanked, 40) == (0, 0), \
        "the keyboard feedback's LED words are zeroed"
    assert struct.unpack_from(LE + "HH", blanked, 36) == (400, 100), \
        "the bell pitch and duration beside them are answered truthfully"
    assert struct.unpack_from(LE + "II", blanked, 56) == (0x2, 0x2), \
        "another feedback class at the same offsets is left alone"
    # a record claiming an impossible length stops the walk instead of looping
    broken = bytearray(body)
    struct.pack_into(LE + "H", broken, 2, 0)
    assert conn.blank_feedback_leds(head, bytes(broken)) == head + bytes(broken)


def test_xkb_events_are_an_allowlist_not_a_block_list():
    # Eleventh pass.  patch_event dropped XkbStateNotify and passed the rest,
    # which left IndicatorStateNotify (4) and ExtensionDeviceNotify (11)
    # pushing the same lock state the polls above now blank -- both measured
    # arriving through the proxy on a Caps Lock press.  Two events are what
    # toolkits need; the other ten are dropped, ActionMessage (9) and
    # AccessXNotify (10) among them, which can carry a keycode.
    conn = rooted_connection()
    conn.profile.note_extension(135, "XKEYBOARD", first_event=85)

    def xkb_event(subtype):
        event = bytearray(32)
        event[0] = 85
        event[1] = subtype
        return bytes(event)

    for subtype in (0, 1):
        assert conn.patch_event(xkb_event(subtype)) is None, subtype
    for subtype in range(2, 12):
        assert conn.patch_event(xkb_event(subtype)) is conn.DROP_EVENT, subtype


def test_randr_reads_pass_and_writes_are_refused():
    conn = make_connection()
    conn.extension_opcodes = {140: "RANDR"}
    assert conn.judge(140, 8, b"")[0] == "allow"       # GetScreenResources
    assert conn.judge(140, 25, b"")[0] == "allow"      # ...ResourcesCurrent
    assert conn.judge(140, 4, b"")[0] == "allow"       # SelectInput
    assert conn.judge(140, 7, b"")[0] == "silent"      # SetScreenSize
    assert conn.judge(140, 18, b"")[0] == "silent"     # AddOutputMode
    assert conn.judge(140, 30, b"")[0] == "silent"     # SetOutputPrimary
    assert callable(conn.judge(140, 21, b"")[0]), "SetCrtcConfig replies"
    assert callable(conn.judge(140, 16, b"")[0]), "CreateMode replies"


def test_shape_cannot_reshape_a_foreign_window():
    conn = make_connection()
    conn.extension_opcodes = {141: "SHAPE"}
    def combine(window, source=OWN):
        # a whole one: operation, kinds, the destination window at offset 4,
        # the offsets, and the source drawable at 12.  It used to be built
        # eight bytes long, which stopped before the source -- and the policy
        # skipped the gate it could not read.  Both ends are fixed now, so the
        # request here is the length a client really sends.
        return struct.pack(LE + "BBBxIhhI", 0, 0, 0, window, 0, 0, source)
    for minor in (1, 2, 3, 4):
        assert conn.judge(141, minor, combine(FOREIGN))[0] == "silent", minor
        assert conn.judge(141, minor, combine(OWN))[0] == "allow", minor
        if minor in xfilter.SHAPE_SOURCE_DRAWABLES:
            # 2 and 3 are gated on a *source* at offset 12 as well, so a body
            # that stops at 8 cannot be judged and is refused rather than
            # skipped.  1 and 4 carry only the destination, at offset 4, which
            # is there -- a request is refused for the fields its gates read,
            # not for being shorter than the protocol's full form.
            assert conn.judge(141, minor, combine(OWN)[:8])[0] != "allow", minor


def test_xfixes_cursor_is_answered_blank():
    conn = make_connection()
    conn.extension_opcodes = {142: "XFIXES"}
    assert conn.judge(142, 3, b"\0" * 8)[0] == "silent"   # SelectCursorInput
    answer = conn.judge(142, 4, b"")[0]                   # GetCursorImage
    reply = answer(7)
    assert reply[0] == 1 and len(reply) == 36
    assert struct.unpack_from(LE + "I", reply, 4)[0] == 1, \
        "the length field has to match the one pixel that follows"
    assert struct.unpack_from(LE + "HH", reply, 12) == (1, 1), "a 1x1 cursor"
    assert reply[32:] == b"\0" * 4, "and a fully transparent one"
    named = conn.judge(142, 25, b"")[0](7)                # ...AndName
    assert len(named) == 36
    assert struct.unpack_from(LE + "I", named, 24)[0] == 0, "no cursor name"
    assert struct.unpack_from(LE + "H", named, 28)[0] == 0, "of zero length"
    # SetWindowShapeRegion is the SHAPE attack arriving through XFIXES
    assert conn.judge(142, 21, struct.pack(LE + "I", FOREIGN))[0] == "silent"
    assert conn.judge(142, 21, struct.pack(LE + "I", OWN))[0] == "allow"


# -- hygiene ---------------------------------------------------------------

def test_an_extension_is_named_in_only_one_list():
    both = xfilter.KNOWN_DENIED_EXTENSIONS & xfilter.ALLOWED_EXTENSIONS
    assert not both, "a capability in both lists is decided by evaluation order"


def test_every_admitted_extension_minor_is_classified_safe_or_gated():
    """The fail-open cure: SAFE and GATED must partition each gated extension's
    allowlist, so no admitted minor is passed on trust at an allow-tail without
    having been deliberately classified.  (The import-time guard enforces this;
    the test states it, and would catch a new minor added to an allowlist
    without being classified.)"""
    partitions = (
        (xfilter.RENDER_SAFE, xfilter.RENDER_GATED, xfilter.RENDER_ALLOWED),
        (xfilter.XFIXES_SAFE, xfilter.XFIXES_GATED, xfilter.XFIXES_ALLOWED),
        (xfilter.XI_SAFE, xfilter.XI_GATED, xfilter.XI_ALLOWED),
        (xfilter.XKB_SAFE, xfilter.XKB_GATED, xfilter.XKB_ALLOWED),
        (xfilter.RANDR_SAFE, xfilter.RANDR_GATED, xfilter.RANDR_ALLOWED),
        (xfilter.SHAPE_SAFE, xfilter.SHAPE_GATED, xfilter.SHAPE_ALLOWED),
        (xfilter.SYNC_SAFE, xfilter.SYNC_GATED, xfilter.SYNC_ALLOWED),
        (xfilter.DBE_SAFE, xfilter.DBE_GATED, xfilter.DBE_ALLOWED),
    )
    for safe, gated, allowed in partitions:
        allowed = set(allowed)
        assert not (safe & gated), "SAFE and GATED overlap"
        assert (safe | gated) == allowed, "SAFE + GATED must cover the allowlist"


def query_extension(name):
    raw = name.encode()
    return (struct.pack(LE + "Hxx", len(raw)) + raw
            + b"\0" * core.pad4(len(raw)))


def test_an_unlisted_extension_is_reported_absent():
    conn = make_connection()
    assert conn.judge(98, 0, query_extension("RENDER"))[0] == "allow"
    assert conn.judge(98, 0, query_extension("XTEST"))[0] == "hide-extension"
    # present on a stock server and on neither list: reporting it present and
    # then blocking every request in it left the client waiting for a reply
    assert conn.judge(98, 0,
                      query_extension("X-Resource"))[0] == "hide-extension"


def change_property(window, prop, fmt, items, data):
    return struct.pack(LE + "IIIBxxxI", window, prop, 31, fmt, items) + data


def test_note_identity_reads_the_property_data():
    conn = make_connection()
    conn.profile.note_atom(200, "WM_CLASS")
    conn.profile.note_atom(201, "_NET_WM_PID")
    conn.profile.note_atom(202, "WM_CLIENT_MACHINE")
    # the data starts at 20, not 24, and the length counts items not bytes
    conn.note_identity(change_property(OWN, 200, 8, 12, b"myapp\0MyApp\0"))
    assert conn.identity.get("class") == "myapp", conn.identity
    conn.note_identity(change_property(OWN, 201, 32, 1,
                                       struct.pack(LE + "I", 4242)))
    assert conn.identity.get("pid") == "4242", conn.identity
    conn.note_identity(change_property(OWN, 202, 8, 4, b"here"))
    assert conn.describe() == "myapp (pid 4242 on here)"


# -- keeping the untrusted set out of the trusted one ----------------------

def test_foreign_resources_cannot_be_drawn_on_or_freed():
    conn = make_connection()
    for name in ("PolyLine", "PolyFillRectangle", "PutImage", "ImageText8",
                 "ClearArea", "FillPoly", "PolyText8"):
        opcode = xfilter._OPCODE[name]
        # drawable at offset 0, graphics context at 4
        assert conn.judge(opcode, 0,
                          struct.pack(LE + "II", FOREIGN, OWN))[0] == "silent", name
        assert conn.judge(opcode, 0,
                          struct.pack(LE + "II", OWN, OWN))[0] == "allow", name
    for name in ("FreeGC", "FreePixmap", "FreeColormap", "FreeCursor",
                 "CloseFont", "ChangeGC", "SetDashes", "RecolorCursor",
                 "InstallColormap", "StoreColors"):
        opcode = xfilter._OPCODE[name]
        assert conn.judge(opcode, 0,
                          struct.pack(LE + "I", FOREIGN))[0] == "silent", name
        assert conn.judge(opcode, 0,
                          struct.pack(LE + "I", OWN))[0] == "allow", name
    # CopyGC names two: reading one client's context into another's is both
    assert conn.judge(xfilter._OPCODE["CopyGC"], 0,
                      struct.pack(LE + "II", OWN, FOREIGN))[0] == "silent"


def test_copyarea_checks_the_destination_as_well_as_the_source():
    conn = make_connection()
    assert conn.judge(62, 0, struct.pack(LE + "III", FOREIGN, OWN, OWN))[0] \
        == "silent", "reading a foreign drawable is capture"
    assert conn.judge(62, 0, struct.pack(LE + "III", OWN, FOREIGN, OWN))[0] \
        == "silent", "writing one paints into somebody else's window"
    assert conn.judge(62, 0, struct.pack(LE + "III", OWN, OWN, OWN))[0] == "allow"


def test_foreign_window_attributes_are_not_writable():
    conn = make_connection()
    CW_CURSOR, CW_BACK_PIXEL, CW_COLORMAP = 0x4000, 0x0002, 0x2000
    for bit, what in ((CW_CURSOR, "cursor"), (CW_BACK_PIXEL, "background"),
                      (CW_COLORMAP, "colormap")):
        body = struct.pack(LE + "III", FOREIGN, bit, 0x1234)
        assert conn.judge(2, 0, body)[0] == "silent", what
        body = struct.pack(LE + "III", OWN, bit, 0x1234)
        assert conn.judge(2, 0, body)[0] == "allow", what
    # the per-client event mask is still judged on its own terms
    mask = xfilter.CW_EVENT_MASK
    assert conn.judge(2, 0, struct.pack(LE + "III", FOREIGN, mask, 0x1)) \
        [0] == "silent", "an input tap is still a tap"
    assert conn.judge(2, 0, struct.pack(LE + "III", FOREIGN, mask, 0x20000)) \
        [0] == "silent", "watching a foreign window's structure is refused too"


def test_substructure_event_masks_do_not_reopen_enumeration():
    """The event stream is the other route to what QueryTree was closed for.

    SubstructureNotify on the root pushes CreateNotify/DestroyNotify/
    ConfigureNotify for every top-level window -- ids, geometry, stacking and
    the timing of every application opening -- for the rest of the session,
    off a single selection.  SubstructureRedirect on the root is worse: it
    makes the client the window manager.  Neither is an input tap, so the
    input-bit check alone let both through.
    """
    conn = rooted_connection()
    SUB_NOTIFY, SUB_REDIRECT = 0x80000, 0x100000
    STRUCTURE, PROPERTY = 0x20000, 0x400000

    def select(window, bits):                 # ChangeWindowAttributes, mask=CWEventMask
        return struct.pack(LE + "III", window, xfilter.CW_EVENT_MASK, bits)

    for bits, what in ((SUB_NOTIFY, "watching every top-level window"),
                       (SUB_REDIRECT, "becoming the window manager")):
        assert conn.judge(2, 0, select(ROOT, bits))[0] == "silent", \
            "on the root: " + what
        assert conn.judge(2, 0, select(FOREIGN, bits))[0] == "silent", \
            "on a foreign window: " + what
        assert conn.judge(2, 0, select(OWN, bits))[0] == "allow", \
            "a client watches its own children: " + what
    # StructureNotify on a foreign window -- the root included -- pushes that
    # window's ConfigureNotify geometry, so it is refused with the rest of the
    # non-allowlisted bits (the tenth-pass fail-open conversion).  A client
    # still learns *its own* window was resized: StructureNotify on an OWN
    # window is allowed.
    assert conn.judge(2, 0, select(ROOT, STRUCTURE))[0] == "silent"
    assert conn.judge(2, 0, select(OWN, STRUCTURE))[0] == "allow", \
        "a client watches the structure of its own windows"
    # root property changes still pass -- how a toolkit follows
    # _NET_CURRENT_DESKTOP and XSETTINGS; PropertyChange is the one allowed bit
    assert conn.judge(2, 0, select(ROOT, PROPERTY))[0] == "allow", \
        "EV-3 is still open, deliberately: see AUDIT.md"


def test_dont_propagate_on_a_foreign_window_is_refused():
    """CWDontPropagate is a per-*window* attribute, not per-client, so setting
    it on a window the client does not own changes that window's event
    propagation for the whole session -- refused like any other foreign
    attribute write.  On the client's own window it is allowed."""
    conn = make_connection()
    CW_DONT_PROPAGATE = 0x1000
    body = struct.pack(LE + "III", FOREIGN, CW_DONT_PROPAGATE, 0x1)
    assert conn.judge(2, 0, body)[0] == "silent"
    own = struct.pack(LE + "III", OWN, CW_DONT_PROPAGATE, 0x1)
    assert conn.judge(2, 0, own)[0] == "allow"


def test_foreign_event_mask_is_an_allowlist():
    """The event mask on a window the client does not own is default-deny: only
    PropertyChange passes, everything else -- catalogued or not -- is refused.
    This is the tenth-pass conversion of a fail-open block-list (which leaked
    StructureNotify, ResizeRedirect, VisibilityChange and ColormapChange by
    omission) into a fail-closed allowlist."""
    conn = rooted_connection()
    mask = xfilter.CW_EVENT_MASK
    def select(window, bits):
        return struct.pack(LE + "III", window, mask, bits)
    refused = ((0x10000, "VisibilityChange"), (0x20000, "StructureNotify"),
               (0x40000, "ResizeRedirect"), (0x800000, "ColormapChange"),
               (0x1, "KeyPress"), (0x40, "PointerMotion"))
    for bits, what in refused:
        assert conn.judge(2, 0, select(FOREIGN, bits))[0] == "silent", what
        assert conn.judge(2, 0, select(ROOT, bits))[0] == "silent", what
        # but a client may select any of these on a window it owns
        assert conn.judge(2, 0, select(OWN, bits))[0] == "allow", what
    # PropertyChange is the one allowed foreign bit; mixing it with a refused
    # one still refuses the whole selection (over-block is safe, leak is not)
    assert conn.judge(2, 0, select(FOREIGN, 0x400000))[0] == "allow"
    assert conn.judge(2, 0, select(FOREIGN, 0x400000 | 0x20000))[0] == "silent"
    # a body too short to carry the event-mask value is refused, not passed
    short = struct.pack(LE + "II", FOREIGN, mask)          # no value word
    assert conn.judge(2, 0, short)[0] in ("silent", "block")


def test_focus_events_on_a_foreign_window_are_refused():
    conn = rooted_connection()
    FOCUS = 0x200000
    def select(window):
        return struct.pack(LE + "III", window, xfilter.CW_EVENT_MASK, FOCUS)
    assert conn.judge(2, 0, select(ROOT))[0] == "silent", \
        "focus transitions across the session are not the client's business"
    assert conn.judge(2, 0, select(FOREIGN))[0] == "silent"
    assert conn.judge(2, 0, select(OWN))[0] == "allow", \
        "every toolkit watches focus on its own windows"


def property_notify(window, atom):
    """A 32-byte PropertyNotify: window at offset 4, atom at offset 8."""
    event = bytearray(32)
    event[0] = 28
    struct.pack_into(LE + "II", event, 4, window, atom)
    return bytes(event)


def test_property_notify_is_filtered_where_the_read_is_refused():
    """EV-3: an event mask cannot name atoms, so the atom is gated on the event.

    Selecting PropertyChangeMask on a foreign window stays allowed, because a
    GTK client must do exactly that on the settings manager's window to notice
    a theme change.  What is withheld is the notification for a property the
    client may not read -- otherwise it learns that WM_NAME changed on a window
    whose title it cannot see, and when.
    """
    conn = rooted_connection()
    conn.profile.note_atom(300, "WM_NAME")
    conn.profile.note_atom(301, "_XSETTINGS_SETTINGS")

    assert conn.patch_event(property_notify(FOREIGN, 300)) is conn.DROP_EVENT, \
        "a title change on a window the client cannot read is a timing channel"
    assert conn.patch_event(property_notify(FOREIGN, 301)) is None, \
        "the settings the client is allowed to read still notify"
    assert conn.patch_event(property_notify(OWN, 300)) is None, \
        "its own properties are its own business"

    # the selection request itself is deliberately still allowed
    assert conn.judge(2, 0, struct.pack(LE + "III", FOREIGN,
                                        xfilter.CW_EVENT_MASK, 0x400000)) \
        [0] == "allow", "EV-3 is closed on the event, not on the selection"

    # an INCR transfer the gate already approved must not stall
    conn.grant_selection(FOREIGN, 0)
    assert conn.patch_event(property_notify(FOREIGN, 300)) is None, \
        "a requestor mid-transfer needs its PropertyNotify"


def test_a_selection_grant_lives_while_the_transfer_is_moving():
    """Twenty-sixth pass: sixty seconds bounds an *idle* grant, not a transfer.

    A grant used to be minted once, at the SelectionRequest, and never
    refreshed, so SELECTION_GRANT_SECONDS was a ceiling on the whole paste.
    Big payloads do not cross in one request -- the owner answers with a type
    of INCR and feeds the data in chunk by chunk, each chunk waiting for the
    requestor to consume the last -- so a slow requestor ran the grant out
    mid-transfer and both ends then waited for each other for ever.  Measured
    with xclip: a nineteen-megabyte paste to a requestor taking five seconds a
    chunk stopped after twelve of nineteen chunks, exactly sixty seconds in,
    where the same transfer with no proxy completed.
    """
    conn = rooted_connection()
    conn.profile.note_atom(300, "WM_NAME")
    prop = 300

    conn.grant_selection(FOREIGN, prop)
    # wind the grant to the brink, the way a long transfer does
    conn.selection_requests[(FOREIGN, prop)] = time.time() + 0.05
    conn.selection_requestors[FOREIGN] = time.time() + 0.05

    # the requestor taking another chunk is what resets the clock
    assert conn.patch_event(property_notify(FOREIGN, prop)) is None, \
        "the notification that a chunk was consumed must reach the owner"
    # ...so the grant outlives the deadline it had when the event arrived
    time.sleep(0.1)
    assert conn.granted(conn.selection_requestors, FOREIGN), \
        "a transfer still moving must not have its grant expire under it"
    assert conn.granted(conn.selection_requests, (FOREIGN, prop)), \
        "the write side of the same grant has to be renewed with it, or the "\
        "owner keeps the event and loses the ChangeProperty that answers it"
    assert conn.judge(18, 0, struct.pack(LE + "IIIBxxxI", FOREIGN, prop,
                                         31, 8, 6) + b"chunk!")[0] == "allow", \
        "the next chunk must still be allowed into the requestor's window"


def test_a_selection_grant_cannot_be_renewed_by_the_client_itself():
    """The reset is driven by the far side, and never revives a dead grant.

    Two ways this could have gone wrong.  Renewing on the client's own writes
    would let it hold a grant open by itself for ever, so the reset is hung on
    the requestor consuming a chunk instead -- and a *forged* PropertyNotify
    would be the client driving that too, the EV-7 trick the SelectionRequest
    arm already refuses, so the SendEvent bit is checked here for the same
    reason.  And an expired grant must stay expired: renewal extends
    permission, it never mints it.
    """
    conn = rooted_connection()
    conn.profile.note_atom(300, "WM_NAME")
    prop = 300

    # a grant that has run out is not brought back, by any event
    conn.grant_selection(FOREIGN, prop)
    conn.selection_requests[(FOREIGN, prop)] = time.time() - 1
    conn.selection_requestors[FOREIGN] = time.time() - 1
    assert conn.patch_event(property_notify(FOREIGN, prop)) is conn.DROP_EVENT, \
        "an expired grant withholds the event"
    assert not conn.renew_selection_grant(FOREIGN, prop), \
        "renewal must not resurrect a grant that has already expired"
    assert not conn.granted(conn.selection_requestors, FOREIGN)

    # A live grant is not extended by an event the client forged itself --
    # asserted against the genuine one in the same breath, so the test pins
    # the *discrimination* rather than merely the absence of renewal.
    for forged, lives_on in ((True, False), (False, True)):
        conn.grant_selection(FOREIGN, prop)
        conn.selection_requestors[FOREIGN] = time.time() + 0.05
        conn.selection_requests[(FOREIGN, prop)] = time.time() + 0.05
        event = bytearray(property_notify(FOREIGN, prop))
        if forged:
            event[0] |= 0x80                   # sent via SendEvent
        conn.patch_event(bytes(event))
        time.sleep(0.1)
        assert conn.granted(conn.selection_requestors, FOREIGN) is lives_on, \
            ("a client that forges the far side's PropertyNotify must not "
             "thereby keep its own grant alive" if forged else
             "the genuine notification must still renew it")


def test_a_withheld_event_is_named_in_the_operation_log():
    """Twenty-sixth pass: the policy's most visible act was its least logged.

    Withholding an event is what makes an application hang rather than report
    an error -- there is no reply for the server to turn into an X error -- and
    it was the one thing the operation log did not record.  The generic-event
    path has named its drops since the tenth pass; the fixed-event path beside
    it returned DROP_EVENT into a bare `continue`.  The run that first measured
    the INCR stall above ended with the log saying that nothing was blocked,
    while the proxy was precisely what had stopped the transfer.
    """
    conn = rooted_connection()
    conn.profile.note_atom(300, "WM_NAME")

    assert conn.patch_event(property_notify(FOREIGN, 300)) is conn.DROP_EVENT
    assert ("event:PropertyNotify", False) in conn.profile.first_seen, \
        "a withheld event must be recorded, and as blocked"
    assert conn.profile.first_seen[("event:PropertyNotify", False)][2] is False

    # ...and recorded once, not once per event: the drop is on the hot path,
    # so a stream of withheld events costs one entry and one set lookup.
    before = len(conn.profile.first_seen)
    for _ in range(5):
        conn.patch_event(property_notify(FOREIGN, 300))
    assert len(conn.profile.first_seen) == before, \
        "the log is one line per (operation, verdict), not one per event"

    # Each withheld channel is named separately, so a log reader can tell
    # which one went quiet rather than seeing one anonymous "event" line.
    # (The key-event drop is driven by who holds the focus, which needs the
    # upstream connection this socketless connection does not have, so the
    # labelling is exercised here and the drop itself on the wire.)
    for label in ("event:KeyPress", "event:XKB2", "event:XI_KeyPress"):
        conn.note_dropped_event(label)
        assert (label, False) in conn.profile.first_seen, label


def test_a_dry_run_reports_the_events_it_would_withhold():
    """Twenty-seventh pass: --dry-run is the mode you look before you leap in.

    The request path has always judged and logged under --dry-run while
    registering no substitution, and the XGE path says the same thing in its
    docstring -- the log still names it, which is the whole point of looking
    before enforcing.  The fixed-event path kept only half of that: a blanket
    early return skipped every arm, so a dry run neither withheld an event nor
    worked out that it would have.  The drops the twenty-sixth pass had just
    made visible were therefore visible only in the mode that also performs
    them -- by which time the application has already hung.
    """
    conn = make_connection(enforce=False)
    conn.root = ROOT
    conn.roots = {ROOT}
    conn.profile.note_atom(300, "WM_NAME")

    # nothing is withheld...
    assert conn.patch_event(property_notify(FOREIGN, 300)) is None, \
        "a dry run must be byte-for-byte an unfiltered one on the wire"
    # ...and the report says what enforcing would cost
    assert ("event:PropertyNotify", False) in conn.profile.first_seen, \
        "a dry run has to name the event it would have withheld"

    # a rewriting arm is equally inert, and for the same reason: KeymapNotify
    # is blanked under enforcement and must pass through untouched here
    keymap = bytearray(32)
    keymap[0] = 11
    keymap[5] = 0x40                       # some key held down
    assert conn.patch_event(bytes(keymap)) is None, \
        "a dry run must not blank the keymap bitmap either"

    # ...while the enforcing connection does both
    live = rooted_connection()
    live.profile.note_atom(300, "WM_NAME")
    assert live.patch_event(property_notify(FOREIGN, 300)) is live.DROP_EVENT
    assert live.patch_event(bytes(keymap)) is not None, \
        "enforcing still blanks it"


def test_an_unreadable_focus_does_not_hand_over_the_keyboard():
    """Twenty-eighth pass: the keylogger defence must not fail open.

    The twenty-third pass allowed the keyboard grab (refusing it stopped menus
    opening) and bounded the *delivery* instead: a key event reaches this client
    only while a window of its own holds the focus.  That question is asked on
    the proxy's own upstream connection, and `_focus_is_ours` answered **True**
    whenever it could not be asked -- no anchor, a dead one, a socket error, an
    error reply.  So losing the oracle reinstated exactly the attack the rule
    exists to stop: a client holding a grab is sent every keystroke, wherever
    the user is typing.

    Answering False unconditionally is not the fix: with no oracle every client
    goes deaf, the focused one included.  The two cases are distinguishable,
    though -- without a grab X delivers keys only to the focused window's chain,
    so an unfocused client is not being sent any and withholding costs nothing;
    with a grab it is being sent all of them.  So the unreadable case is "ours"
    only for a client that is not holding the keyboard.
    """
    def key(code=2):
        event = bytearray(32)
        event[0] = code
        return bytes(event)

    saved_anchor, saved_cache = xfilter._anchor, xfilter._focus_cache
    try:
        xfilter._anchor = None                 # the focus cannot be read
        xfilter._focus_cache = (0, 0)

        plain = rooted_connection()
        assert plain.patch_event(key()) is None, \
            "a client with no grab must keep its own keys when the oracle is " \
            "gone -- it is not being sent anyone else's"

        for name, opcode, minor, body in (
                ("GrabKeyboard", 31, 0,
                 struct.pack(LE + "IHBB", OWN, 0, 0, 0) + b"\0" * 8),
                ("XI1 GrabDevice", 131, 13, struct.pack(LE + "I", OWN) + b"\0" * 16),
                ("XI2 XIGrabDevice", 131, 51, struct.pack(LE + "I", OWN) + b"\0" * 20)):
            conn = rooted_connection()
            conn.extension_opcodes = {131: "XInputExtension"}
            conn.judge(opcode, minor, body)
            assert conn.keyboard_grabbed, "%s must be remembered" % name
            assert conn.patch_event(key()) is conn.DROP_EVENT, \
                "%s + an unreadable focus is the keylogger" % name
            assert conn.patch_event(key(3)) is conn.DROP_EVENT, name

        # and the grab is given back when the menu closes
        for opcode, minor in ((32, 0), (131, 14), (131, 52)):
            conn = rooted_connection()
            conn.extension_opcodes = {131: "XInputExtension"}
            conn.judge(31, 0, struct.pack(LE + "IHBB", OWN, 0, 0, 0) + b"\0" * 8)
            conn.judge(opcode, minor, b"\0" * 8)
            assert not conn.keyboard_grabbed, \
                "an ungrab has to clear it, or one menu marks the client for life"
            assert conn.patch_event(key()) is None
    finally:
        xfilter._anchor, xfilter._focus_cache = saved_anchor, saved_cache


def test_keymap_notify_is_answered_with_no_keys_down():
    """EV-5: the event twin of QueryKeymap, which is already answered blank.

    KeymapNotify carries a 32-byte bitmap of every key physically down, and
    the server sends it after every EnterNotify and FocusIn on a window that
    selected KeymapState.  It is the one core event with neither a window nor
    a sequence number, so there is nothing in it to preserve but the code.
    """
    conn = rooted_connection()
    event = bytearray(32)
    event[0] = 11
    event[5] = 0x40            # some key held down
    event[9] = 0x02
    patched = conn.patch_event(bytes(event))
    assert patched is not None, "the bitmap must not pass through"
    assert patched[0] == 11, "still a KeymapNotify"
    assert patched[1:] == b"\0" * 31, "and it reports no keys down"


def test_get_input_focus_hides_another_client_s_window():
    """OF-1: truthful about the client's own focus, silent about anyone's else.

    Blanking unconditionally would answer "nobody has focus" even when the
    client itself does, and a toolkit asking whether it holds focus would
    believe it does not.
    """
    conn = rooted_connection()
    verdict, reason = conn.judge(43, 0, b"")
    assert isinstance(verdict, tuple) and verdict[0] == "scrub-foreign", \
        "the request is forwarded and its reply scoped"
    assert verdict[1] == ([8], 0), \
        "the focus window is at offset 8 of the reply, blanked to None"

    def reply_naming(window):
        head = bytearray(32)
        head[0] = 1
        struct.pack_into(LE + "I", head, 8, window)
        return bytes(head)

    own = conn.scrub_foreign_windows(reply_naming(OWN), b"", [8])
    assert struct.unpack_from(LE + "I", own, 8)[0] == OWN, \
        "a client must still learn that it has the focus itself"
    foreign = conn.scrub_foreign_windows(reply_naming(FOREIGN), b"", [8])
    assert struct.unpack_from(LE + "I", foreign, 8)[0] == 0, \
        "another client's focus reads as None"
    root = conn.scrub_foreign_windows(reply_naming(ROOT), b"", [8])
    assert struct.unpack_from(LE + "I", root, 8)[0] == ROOT, \
        "PointerRoot focus is not somebody's private window"


class _Recorder:
    """Stands in for the upstream socket: remembers what was forwarded."""

    def __init__(self):
        self.sent = []

    def sendall(self, data):
        self.sent.append(data)


class _Answer:
    """Stands in for the user at the prompt."""

    def __init__(self, said_yes):
        self.said_yes = said_yes

    def decide(self, *args, **kwargs):
        return self.said_yes


def _asked_and_answered(said_yes):
    conn = make_connection(gate_mode="ask")
    conn.gate = _Answer(said_yes)
    conn.server = _Recorder()
    conn.alert_new = False
    head = struct.pack(LE + "BBH", 24, 0, 6)
    conn.forward(24, 0, head, convert_selection(OWN, 100))
    return conn


def test_the_log_records_what_the_user_decided_not_that_they_were_asked():
    # Twenty-fifth pass.  "ask" is a question, not an outcome, and logging it as
    # one made the operation log say `core:ConvertSelection blocked` about a
    # paste the user had just allowed -- measured end to end on a nested
    # desktop, where the clipboard arrived in the filtered application while
    # the log denied that it had.  The log is the record of what the policy
    # did, so it is written after the answer.
    allowed = _asked_and_answered(True)
    verdicts = {key[1] for key in allowed.profile.first_seen}
    assert verdicts == {True}, "the user said yes, so the log says allowed"
    assert allowed.server.sent, "and the request went upstream"

    refused = _asked_and_answered(False)
    verdicts = {key[1] for key in refused.profile.first_seen}
    assert verdicts == {False}, "the user said no, so the log says blocked"


def test_the_gate_offers_the_setting_that_would_have_allowed_it():
    """A refusal a flag governs should say so, once.

    "blocked" on its own reads as a defect: what the user notices is that copy
    and paste stopped working, with nothing to say a setting controls it.
    """
    conn = make_connection(gate_mode="deny")
    conn.alert_new = False
    # reading the clipboard, then taking it -- two distinct operations
    conn.sentinel(24, 0, "gate", xfilter.GATE_REFUSED)
    assert conn.profile.gate_hinted, "the first gate refusal offers the hint"
    conn.sentinel(22, 0, "silent", xfilter.GATE_OWNER_REFUSED)
    assert conn.profile.note_gate_hint() is False, "and it is offered once only"

    # a refusal that no flag governs must not advertise one
    other = make_connection(gate_mode="deny")
    other.alert_new = False
    other.sentinel(73, 0, "silent", "screen capture")
    assert not other.profile.gate_hinted

    # nor should it appear when the gate is not the thing refusing
    asking = make_connection(gate_mode="ask")
    asking.alert_new = False
    asking.sentinel(24, 0, "silent", xfilter.GATE_REFUSED)
    assert not asking.profile.gate_hinted, \
        "under --gate ask the user was already asked"


def test_server_global_font_path_is_refused():
    conn = make_connection()
    assert conn.judge(51, 0, b"\0" * 4)[0] == "silent", \
        "emptying the font path breaks every other client in the session"
    assert conn.judge(52, 0, b"")[0] == "allow", "reading it is fine"


def test_an_unparsable_request_is_blocked_not_passed():
    # A body too short for the field a rule reads must not skip the rule and
    # be forwarded: not knowing what a request does is the reason to refuse
    # it, not a reason to trust it.
    conn = make_connection()
    conn.server = type("S", (), {"sendall": lambda _s, d: sent.append(d)})()
    sent = []
    truncated = struct.pack(LE + "I", FOREIGN)      # needs 8 bytes, has 4
    try:
        conn.judge(2, 0, truncated)
        raise AssertionError("expected the policy to fail parsing this")
    except struct.error:
        pass
    conn.forward(2, 0, struct.pack(LE + "BBH", 2, 0, 2), truncated)
    assert sent and sent[0][0] == xfilter.NOOP, \
        "an unparsable request must be replaced, not forwarded"


# -- nothing unknown passes, anywhere --------------------------------------

def inspected_connection():
    conn = make_connection()
    conn.extension_opcodes = {131: "XInputExtension", 135: "XKEYBOARD",
                              139: "RENDER", 140: "RANDR", 141: "SHAPE",
                              142: "XFIXES", 143: "SYNC", 144: "DOUBLE-BUFFER",
                              145: "XINERAMA", 146: "XC-MISC",
                              147: "Generic Event Extension",
                              148: "BIG-REQUESTS"}
    return conn


def test_no_inspected_extension_passes_an_unknown_request():
    # The heart of the project: a request nobody has looked at is refused,
    # not forwarded.  This must hold inside every inspected extension, not
    # only at the core protocol and the extension allowlist.
    conn = inspected_connection()
    for major, name in sorted(conn.extension_opcodes.items()):
        verdict, _ = conn.judge(major, 200, b"\0" * 32)
        assert verdict != "allow", "%s passed an unknown minor opcode" % name


def test_xinput_input_state_and_device_writes_are_refused():
    conn = inspected_connection()
    # QueryDeviceState returns the keys and buttons currently down for a
    # device -- the XInput twin of QueryKeymap -- and was passing
    assert callable(conn.judge(131, 30, b"\0" * 32)[0]), "QueryDeviceState"
    # the twin of the blocked core GetMotionEvents
    assert callable(conn.judge(131, 10, b"\0" * 32)[0]), "GetDeviceMotionEvents"
    # the XInput1 twins of the core and XKEYBOARD remap rules
    assert conn.judge(131, 25, b"\0" * 32)[0] == "silent", "ChangeDeviceKeyMapping"
    assert callable(conn.judge(131, 27, b"\0" * 32)[0]), "SetDeviceModifierMapping"
    assert callable(conn.judge(131, 29, b"\0" * 32)[0]), "SetDeviceButtonMapping"
    # reattaching devices, and the server-global device properties
    assert conn.judge(131, 43, b"\0" * 32)[0] == "silent", "XIChangeHierarchy"
    assert conn.judge(131, 57, b"\0" * 32)[0] == "silent", "XIChangeProperty"
    # while the queries every toolkit makes still pass
    for minor in (2, 47, 48, 46):
        assert conn.judge(131, minor,
                          struct.pack(LE + "IHH", OWN, 0, 0))[0] == "allow", minor


def test_render_and_xfixes_keep_resources_apart():
    conn = inspected_connection()
    # FreePicture destroys another client's drawing surface
    assert conn.judge(139, 7, struct.pack(LE + "I", FOREIGN))[0] == "silent"
    assert conn.judge(139, 7, struct.pack(LE + "I", OWN))[0] == "allow"
    # Composite: op+pad, src, mask, dst -- painting into a foreign picture
    composite = lambda dst: struct.pack(LE + "IIII", 0, OWN, 0, dst)
    assert conn.judge(139, 8, composite(FOREIGN))[0] == "silent"
    assert conn.judge(139, 8, composite(OWN))[0] == "allow"
    # a PICTFORMAT is allocated by the *server* and must not read as foreign:
    # CompositeGlyphs names one at offset 12, between dst and the glyph set
    glyphs = struct.pack(LE + "IIIII", 0, OWN, OWN, 0x99999, OWN)
    assert conn.judge(139, 23, glyphs)[0] == "allow", \
        "the server's picture formats are not another client's resources"
    # XFIXES regions and the graphics context a clip region is set on.
    # SetGCClipRegion is gc(0), region(4), xOrigin(8), yOrigin(10).
    assert conn.judge(142, 10, struct.pack(LE + "I", FOREIGN))[0] == "silent"
    assert conn.judge(142, 20, struct.pack(LE + "IIhh", FOREIGN, OWN, 0, 0))[0] \
        == "silent", "setting a clip region on another client's context"
    assert conn.judge(142, 20, struct.pack(LE + "IIhh", OWN, OWN, 0, 0))[0] \
        == "allow"


def test_safe_core_names_nothing_that_can_be_foreign():
    # SAFE_CORE is passed with no argument inspection at all, so it must hold
    # only requests that cannot name another client's resource.  Anything that
    # can belongs in a rule instead.
    gated = (xfilter.WINDOW_WRITE_REQUESTS
             | set(xfilter.FOREIGN_RESOURCE_REQUESTS)
             | set(xfilter.SCREEN_REFERENCE_REQUESTS)
             | set(xfilter.SCREEN_REFERENCE_REPLIES)
             | set(xfilter.CURSOR_SOURCE_REQUESTS)
             | {1, 3, 14, 22, 40, 51})   # CreateWindow, the metadata reads,
                                         # SetSelectionOwner, SetFontPath
    overlap = sorted(xfilter.CORE_NAMES[o] for o in gated & xfilter.SAFE_CORE)
    assert not overlap, \
        "on the unchecked list and gated by a rule: %s" % ", ".join(overlap)


def test_a_window_may_not_be_created_inside_a_foreign_window():
    conn = make_connection()
    conn.root = ROOT
    conn.roots = {ROOT}
    def create(parent):
        return struct.pack(LE + "IIhhHHHII", OWN, parent, 0, 0, 10, 10, 0, 0, 0)
    assert conn.judge(1, 0, create(ROOT))[0] == "allow", \
        "every top-level window has a root as its parent"
    assert conn.judge(1, 0, create(OWN))[0] == "allow"
    assert conn.judge(1, 0, create(FOREIGN))[0] == "silent", \
        "an overlay inside a trusted window is ReparentWindow by another route"


def test_find_root_collects_every_screen():
    # one screen, one depth, one visual -- the shape find_root walks
    body = bytearray(32)
    struct.pack_into(LE + "H", body, 16, 0)        # no vendor string
    body[20], body[21] = 1, 0                      # 1 screen, 0 formats
    screen = bytearray(40)
    struct.pack_into(LE + "I", screen, 0, ROOT)
    screen[39] = 1                                 # one DEPTH
    depth = bytearray(8)
    struct.pack_into(LE + "H", depth, 2, 1)        # one VISUALTYPE
    conn = make_connection()
    conn.find_root(bytes(body + screen + depth + bytearray(24)))
    assert conn.root == ROOT and conn.roots == {ROOT}, (conn.root, conn.roots)


# -- isolation rather than blocking ----------------------------------------

def track_window(conn, window, width, height, mapped=True, override=False,
                 parent=None):
    """Teach the shared window model about one of the application's windows."""
    conn.profile.note_window(window, ROOT if parent is None else parent,
                             width, height, override)
    if mapped:
        conn.profile.note_mapped(window, True)
    return window


def rooted_connection():
    conn = make_connection()
    conn.root = ROOT
    conn.roots = {ROOT}
    return conn


def test_screen_references_may_name_a_root_but_not_a_foreign_window():
    # CreateGC and friends name a drawable only to pick a screen and depth,
    # and creating one against the root is a near-universal idiom -- so the
    # rule scopes them rather than blocking them.
    conn = rooted_connection()
    for opcode, offset in ((55, 4), (53, 4), (78, 4)):   # GC, Pixmap, Colormap
        def body(drawable):
            raw = bytearray(12)
            struct.pack_into(LE + "I", raw, 0, OWN)
            struct.pack_into(LE + "I", raw, offset, drawable)  # noqa: B023
            #  ^ late binding is harmless: body() is only ever called
            #    inside the iteration that defined it
            return bytes(raw)
        assert conn.judge(opcode, 0, body(ROOT))[0] == "allow", opcode
        assert conn.judge(opcode, 0, body(OWN))[0] == "allow", opcode
        assert conn.judge(opcode, 0, body(FOREIGN))[0] == "silent", opcode
    # QueryBestSize replies, so its refusal echoes the size that was asked for
    answer = conn.judge(97, 0, struct.pack(LE + "IHH", FOREIGN, 64, 48))[0]
    assert callable(answer)
    assert struct.unpack_from(LE + "HH", answer(3), 8) == (64, 48)
    # a cursor built from another client's pixmap
    assert conn.judge(93, 0, struct.pack(LE + "III", OWN, FOREIGN, 0))[0] \
        == "silent"
    assert conn.judge(93, 0, struct.pack(LE + "III", OWN, OWN, 0))[0] == "allow"


def test_foreign_window_metadata_is_answered_not_refused():
    conn = rooted_connection()
    # the root is what a client reads for the screen size
    assert conn.judge(14, 0, struct.pack(LE + "I", ROOT))[0] == "allow"
    assert conn.judge(14, 0, struct.pack(LE + "I", OWN))[0] == "allow"
    answer = conn.judge(14, 0, struct.pack(LE + "I", FOREIGN))[0]
    assert callable(answer), "an error would kill simple Xlib clients"
    reply = answer(5)
    assert len(reply) == 32 and reply[0] == 1
    assert struct.unpack_from(LE + "I", reply, 8)[0] == ROOT
    assert struct.unpack_from(LE + "HH", reply, 16) == (0, 0), "no size given"

    assert conn.judge(3, 0, struct.pack(LE + "I", OWN))[0] == "allow"
    attrs = conn.judge(3, 0, struct.pack(LE + "I", FOREIGN))[0](5)
    assert len(attrs) == 44, "GetWindowAttributes replies are 44 bytes"
    assert struct.unpack_from(LE + "I", attrs, 4)[0] == 3, "length must match"
    assert struct.unpack_from(LE + "I", attrs, 36)[0] == 0, "no event masks"


def test_translate_coordinates_still_serves_menus_and_drag_and_drop():
    conn = rooted_connection()
    def translate(src, dst):
        return struct.pack(LE + "IIhh", src, dst, 10, 10)
    # A drag source asks root-to-root; menus translate their own window
    # against a root.  Neither names a foreign window, so both are forwarded
    # -- as a scrub, which passes the request and blanks only the reply's
    # child field, so the coordinates a menu needs still come back.
    for src, dst in ((ROOT, ROOT), (OWN, ROOT), (ROOT, OWN)):
        verdict, _ = conn.judge(40, 0, translate(src, dst))
        assert verdict == ("scrub", [(8, 4)]), (src, dst, verdict)
    # naming another client's window is the enumeration this closes, and that
    # one is refused outright rather than merely scrubbed
    assert callable(conn.judge(40, 0, translate(OWN, FOREIGN))[0])
    assert callable(conn.judge(40, 0, translate(FOREIGN, OWN))[0])


def test_hiding_foreign_windows_is_not_switchable_at_runtime():
    # A security rule that a command-line flag can turn off is a rule that
    # gets turned off.  QueryTree hiding is a policy constant, edited in the
    # source like SAFE_CORE is, so disabling it is a diff and not an argument.
    assert xfilter.DENY_QUERYTREE is True
    conn = rooted_connection()
    verdict, _ = conn.judge(15, 0, struct.pack(LE + "I", ROOT))
    assert callable(verdict), "the root's children must not be listed"
    tree = verdict(4)
    assert struct.unpack_from(LE + "I", tree, 8)[0] == ROOT, "root reported"
    assert struct.unpack_from(LE + "H", tree, 16)[0] == 0, "and no children"
    # a client still reads its own tree, which is how it finds the frame the
    # window manager reparented it into
    assert conn.judge(15, 0, struct.pack(LE + "I", OWN))[0] == "allow"


# -- sixth pass: SH-1, XI-1, EV-7 ------------------------------------------

def test_shape_reads_of_a_foreign_window_are_blanked():
    # SH-1.  judge_shape gated the reshape writes and forwarded the reads, so
    # ShapeQueryExtents/GetRectangles handed back a foreign window's size and
    # outline -- the metadata GetGeometry is blanked to withhold, one opcode
    # over.  On a foreign window the reads must answer blank, not truthfully,
    # and not by an error that would kill a simple Xlib client.
    conn = rooted_connection()
    conn.extension_opcodes = {141: "SHAPE"}
    for minor in (5, 7, 8):            # QueryExtents, InputSelected, GetRectangles
        assert conn.judge(141, minor, struct.pack(LE + "I", OWN))[0] == "allow", minor
        assert conn.judge(141, minor, struct.pack(LE + "I", ROOT))[0] == "allow", minor
        verdict = conn.judge(141, minor, struct.pack(LE + "I", FOREIGN))[0]
        assert callable(verdict), minor
        reply = verdict(7)
        assert len(reply) == 32 and reply[0] == 1, minor
        assert reply[1] == 0, "header state byte (enabled/ordering) blank"
        assert all(b == 0 for b in reply[8:]), "no size, no rectangles, no state"
    # ShapeSelectInput watches a foreign window reshape; refused, no reply
    assert conn.judge(141, 6, struct.pack(LE + "I", FOREIGN))[0] == "silent"
    assert conn.judge(141, 6, struct.pack(LE + "I", OWN))[0] == "allow"


def test_shape_cannot_borrow_a_foreign_windows_outline():
    # The destination of a reshape was gated and the *source* was not.
    # ShapeMask (2) and ShapeCombine (3) copy a shape from a drawable at
    # offset 12 onto the window at offset 4, so combining a foreign window
    # into one you own and then reading your own window's shape -- allowed,
    # since you own it -- hands back the outline SH-1 blanks.  The read-back
    # channel CopyArea's source check closes, arriving through SHAPE.
    conn = rooted_connection()
    conn.extension_opcodes = {141: "SHAPE"}

    def combine(dest, source):
        return struct.pack(LE + "BBBB I hh I", 0, 0, 0, 0, dest, 0, 0, source)

    for minor in (2, 3):
        assert conn.judge(141, minor, combine(OWN, FOREIGN))[0] == "silent", minor
        assert conn.judge(141, minor, combine(OWN, OWN))[0] == "allow", minor
        # the destination check still stands, whatever the source is
        assert conn.judge(141, minor, combine(FOREIGN, OWN))[0] == "silent", minor


def test_a_clip_region_is_checked_where_the_region_actually_is():
    # SetGCClipRegion and SetPictureClipRegion are gc-or-picture(0),
    # region(4), xOrigin(8), yOrigin(10).  Both were listed against offset 8,
    # so the check read the two 16-bit origins as a resource id: wrong in both
    # directions at once.  A foreign region went through unexamined, and an
    # ordinary request with a non-zero clip origin was dropped for naming a
    # "resource" that was a pair of coordinates.
    conn = rooted_connection()
    conn.extension_opcodes = {142: "XFIXES"}
    for minor in (20, 22):
        clip = lambda region, x, y: struct.pack(LE + "IIhh", OWN, region, x, y)
        assert conn.judge(142, minor, clip(FOREIGN, 0, 0))[0] == "silent", minor
        assert conn.judge(142, minor, clip(OWN, 10, 20))[0] == "allow", \
            "a clip origin is not a resource id (minor %d)" % minor
        assert conn.judge(142, minor, clip(0, 0, 0))[0] == "allow", \
            "None means no clipping (minor %d)" % minor


def test_a_window_cannot_be_shaped_with_a_foreign_region():
    # SetWindowShapeRegion is dest(0), destKind(4), xOff(8), yOff(10),
    # region(12).  Only the window was checked, so shaping a window you own
    # with another client's region and reading that window's shape back is the
    # ShapeCombine read-back with a region in place of the source window.
    conn = rooted_connection()
    conn.extension_opcodes = {142: "XFIXES"}

    def shape(dest, region):
        return struct.pack(LE + "I BBH hh I", dest, 0, 0, 0, 0, 0, region)

    assert conn.judge(142, 21, shape(OWN, FOREIGN))[0] == "silent"
    assert conn.judge(142, 21, shape(OWN, OWN))[0] == "allow"
    assert conn.judge(142, 21, shape(FOREIGN, OWN))[0] == "silent"


def test_xinput_window_reads_hide_another_clients_input_wiring():
    # Minor 7 was blanked on a foreign window (XI-1's sibling) and its twins
    # were not: GetDeviceDontPropagateList (9) reports the window's
    # do-not-propagate list -- the read side of minor 8, already refused --
    # and XIGetClientPointer (45) names the pointer device of whichever client
    # owns the window.  Both answer blank on a foreign window now.
    conn = rooted_connection()
    conn.extension_opcodes = {131: "XInputExtension"}
    for minor in (7, 9, 45):
        assert conn.judge(131, minor, struct.pack(LE + "I", OWN))[0] == "allow", minor
        assert conn.judge(131, minor, struct.pack(LE + "I", ROOT))[0] == "allow", minor
        verdict = conn.judge(131, minor, struct.pack(LE + "I", FOREIGN))[0]
        assert callable(verdict), minor
        reply = verdict(7)
        assert len(reply) == 32 and reply[0] == 1, minor
        assert all(b == 0 for b in reply[8:]), \
            "an empty count is a coherent answer (minor %d)" % minor
    # XIGetSelectedEvents (60) reports only what the *asking* client selected,
    # so there is nothing of anyone else's to hide and it stays untouched.
    assert conn.judge(131, 60, struct.pack(LE + "I", FOREIGN))[0] == "allow"


def test_a_foreign_pointer_barrier_cannot_be_released():
    # XIBarrierReleasePointer walks a list: num_barriers(0), then twelve-byte
    # entries with the barrier at +4.  Releasing another client's barrier lets
    # the pointer cross a boundary that client put up.
    conn = rooted_connection()
    conn.extension_opcodes = {131: "XInputExtension"}

    def release(*barriers):
        body = struct.pack(LE + "I", len(barriers))
        for barrier in barriers:
            body += struct.pack(LE + "HHII", 2, 0, barrier, 7)
        return body

    assert conn.judge(131, 61, release(OWN))[0] == "allow"
    assert conn.judge(131, 61, release(FOREIGN))[0] == "silent"
    # a foreign barrier anywhere in the list condemns the request
    assert conn.judge(131, 61, release(OWN, OWN, FOREIGN))[0] == "silent"
    # a count that outruns the body must not read past it
    assert conn.judge(131, 61, struct.pack(LE + "I", 4096))[0] == "allow"


def test_a_sync_fence_names_a_screen_not_a_foreign_window():
    # CreateFence is the one SYNC Create whose first field is not the new id:
    # it is drawable(0), fid(4).  "Creates are not gated" skipped it, so a
    # fence could be made against another client's window.  A drawable here
    # only names a screen, so a root passes.
    conn = rooted_connection()
    conn.extension_opcodes = {143: "SYNC"}

    def create_fence(drawable):
        return struct.pack(LE + "IIBBH", drawable, OWN, 0, 0, 0)

    assert conn.judge(143, 14, create_fence(OWN))[0] == "allow"
    assert conn.judge(143, 14, create_fence(ROOT))[0] == "allow"
    assert conn.judge(143, 14, create_fence(FOREIGN))[0] == "silent"


def test_xinput_focus_reads_hide_a_foreign_window():
    # XI-1.  GetInputFocus was scrubbed (OF-1), but XIGetFocus (minor 50) and
    # GetDeviceFocus (minor 20) returned the focus window unscrubbed, reopening
    # the same focus trace through the sibling extension.
    conn = rooted_connection()
    conn.extension_opcodes = {131: "XInputExtension"}
    for minor in (20, 50):
        assert conn.judge(131, minor, struct.pack(LE + "I", 3)) \
            == (("scrub-foreign", ([8], 0)), "foreign focus window"), minor
    # the reply scrubber blanks the focus field (offset 8) only when foreign
    head = bytearray(32)
    head[0] = 1
    struct.pack_into(LE + "I", head, 8, FOREIGN)
    scrubbed = conn.scrub_foreign_windows(bytes(head), b"", [8])
    assert struct.unpack_from(LE + "I", scrubbed, 8)[0] == 0, "foreign focus blanked"
    struct.pack_into(LE + "I", head, 8, OWN)
    kept = conn.scrub_foreign_windows(bytes(head), b"", [8])
    assert struct.unpack_from(LE + "I", kept, 8)[0] == OWN, "own focus kept"


def test_a_forged_selection_request_does_not_unlock_a_foreign_write():
    # EV-7.  patch_event learned write-grants from SelectionRequest events but
    # masked off the 0x80 SendEvent bit, so a self-sent forgery was trusted
    # like the server's and unlocked foreign ChangeProperty.
    conn = make_connection()
    conn.profile.note_atom(300, "SOME_PROP")
    foreign_write = struct.pack(LE + "IIIBxxxI", FOREIGN, 300, 31, 8, 4) + b"data"
    assert conn.judge(18, 0, foreign_write)[0] == "silent"

    def selection_request(synthetic):
        ev = bytearray(32)
        ev[0] = 30 | (0x80 if synthetic else 0)
        struct.pack_into(LE + "I", ev, 12, FOREIGN)     # requestor
        struct.pack_into(LE + "I", ev, 24, 300)         # property
        return bytes(ev)

    conn.patch_event(selection_request(synthetic=True))
    assert conn.judge(18, 0, foreign_write)[0] == "silent", \
        "a forged SelectionRequest must not unlock a foreign write"
    assert (FOREIGN, 300) not in conn.selection_requests
    assert FOREIGN not in conn.selection_requestors

    # a genuine, server-generated one still enables the paste-out it exists for
    conn.patch_event(selection_request(synthetic=False))
    assert conn.judge(18, 0, foreign_write)[0] == "allow", \
        "real paste-out must still work"
    assert (FOREIGN, 300) in conn.selection_requests


# -- seventh pass: every allowed extension is inspected --------------------

def test_every_allowed_extension_is_inspected():
    # The invariant, now structural: the one allowlist IS the inspector table,
    # so "allowed" and "inspected" are the same fact and cannot drift.  Every
    # value names a real method on PolicyConnection, and nothing is allowed
    # without one.
    assert xfilter.ALLOWED_EXTENSIONS == frozenset(xfilter.EXTENSION_INSPECTORS)
    for name, method in xfilter.EXTENSION_INSPECTORS.items():
        assert callable(getattr(xfilter.PolicyConnection, method, None)), name
    # and denied and allowed stay disjoint
    assert not (xfilter.KNOWN_DENIED_EXTENSIONS & xfilter.ALLOWED_EXTENSIONS)


def test_sync_gates_operations_on_a_foreign_resource():
    conn = make_connection()
    conn.extension_opcodes = {143: "SYNC"}
    # modify/destroy a counter/alarm/fence, or set a client's priority, by an
    # id that is another client's -> refused; the same on the client's own ->
    # allowed.
    for minor in (3, 4, 6, 9, 11, 12, 15, 16, 17):
        assert conn.judge(143, minor,
                          struct.pack(LE + "I", FOREIGN) + b"\0" * 8)[0] \
            == "silent", minor
        assert conn.judge(143, minor,
                          struct.pack(LE + "I", OWN) + b"\0" * 8)[0] \
            == "allow", minor
    # creating and querying the client's own objects is fine
    assert conn.judge(143, 2, struct.pack(LE + "I", OWN) + b"\0" * 8)[0] == "allow"
    assert conn.judge(143, 5, struct.pack(LE + "I", OWN))[0] == "allow"
    # but the READ side on a FOREIGN object is a disclosure, not a nuisance --
    # QueryCounter on the system IDLETIME counter is a whole-session idle trace,
    # QueryAlarm/QueryFence/GetPriority read another client's state.  Each
    # expects a reply, so a foreign one is answered blank rather than dropped.
    for minor in (5, 10, 13, 18):                    # Query{Counter,Alarm,Fence}/GetPriority
        assert callable(conn.judge(143, minor, struct.pack(LE + "I", FOREIGN))[0]), \
            "foreign sync read must be blanked, minor %d" % minor
        assert conn.judge(143, minor, struct.pack(LE + "I", OWN))[0] == "allow", minor
    # Await/CreateAlarm/ChangeAlarm that *watch* a foreign counter (the system
    # IDLETIME counter) are the timing twin of the QueryCounter read: refused on
    # a foreign counter, allowed on the client's own.
    await_foreign = struct.pack(LE + "I", FOREIGN) + b"\0" * 24   # one WAITCONDITION
    await_own = struct.pack(LE + "I", OWN) + b"\0" * 24
    assert conn.judge(143, 7, await_foreign)[0] == "silent"
    assert conn.judge(143, 7, await_own)[0] == "allow"
    # CreateAlarm: id(0), value-mask=XSyncCACounter(0x1), counter(8)
    alarm_foreign = struct.pack(LE + "III", OWN, 0x1, FOREIGN) + b"\0" * 8
    alarm_own = struct.pack(LE + "III", OWN, 0x1, OWN) + b"\0" * 8
    assert conn.judge(143, 8, alarm_foreign)[0] == "silent"
    assert conn.judge(143, 8, alarm_own)[0] == "allow"
    # an unknown minor is refused, not forwarded
    assert conn.judge(143, 200, b"\0" * 32)[0] != "allow"


def test_double_buffer_gates_foreign_windows_and_buffers():
    conn = make_connection()
    conn.extension_opcodes = {144: "DOUBLE-BUFFER"}
    def alloc(window):
        return struct.pack(LE + "III", window, OWN | 0x22, 0)
    assert conn.judge(144, 1, alloc(FOREIGN))[0] == "silent"
    assert conn.judge(144, 1, alloc(OWN))[0] == "allow"
    assert conn.judge(144, 2, struct.pack(LE + "I", FOREIGN))[0] == "silent"
    assert conn.judge(144, 2, struct.pack(LE + "I", OWN))[0] == "allow"
    def swap(window):
        return struct.pack(LE + "I", 1) + struct.pack(LE + "IBxxx", window, 0)
    assert conn.judge(144, 3, swap(FOREIGN))[0] == "silent"
    assert conn.judge(144, 3, swap(OWN))[0] == "allow"
    # GetBackBufferAttributes on a foreign buffer -> blank reply, not an error
    verdict = conn.judge(144, 7, struct.pack(LE + "I", FOREIGN))[0]
    assert callable(verdict) and verdict(5)[0] == 1
    assert conn.judge(144, 200, b"\0" * 32)[0] != "allow"


def test_simple_extensions_allow_known_minors_and_refuse_unknown():
    conn = make_connection()
    conn.extension_opcodes = {145: "XINERAMA", 146: "XC-MISC",
                              147: "Generic Event Extension",
                              148: "BIG-REQUESTS"}
    for major, known, unknown in ((145, 5, 6), (146, 2, 3),
                                  (147, 0, 1), (148, 0, 1)):
        assert conn.judge(major, known, b"\0" * 8)[0] == "allow", (major, known)
        assert conn.judge(major, unknown, b"\0" * 8)[0] != "allow", (major, unknown)


def test_synthetic_input_to_focus_or_pointer_is_refused():
    # SE-1: SendEvent of a forged Key/Button/Motion event to PointerWindow(0)
    # or InputFocus(1) lands on whatever window is focused or under the pointer
    # -- a trusted one, as a rule -- so it is refused: the write-direction twin
    # of the input taps the policy blocks.  It reached past the foreign-window
    # check because 0 and 1 are special destinations, not XIDs.
    conn = make_connection()
    def send(dest, code):
        ev = bytearray(32)
        ev[0] = code
        return struct.pack(LE + "II", dest, 0) + bytes(ev)
    for dest in (0, 1):
        for code in (2, 3, 4, 5, 6):        # Key/Button press+release, Motion
            assert conn.judge(25, 0, send(dest, code))[0] == "silent", (dest, code)
    # non-input events to those destinations still pass (e.g. ClientMessage)
    assert conn.judge(25, 0, send(0, 33))[0] == "allow"
    # and a client sending input to its *own* window is harmless
    assert conn.judge(25, 0, send(OWN, 2))[0] == "allow"


# -- fullscreen-overlay defence (desktop / login spoofing) -----------------

FS_W, FS_H = 1920, 1080          # a fullscreen size
SMALL_W, SMALL_H = 300, 200      # a menu-sized window


def fs_connection():
    conn = rooted_connection()
    conn.screen_width, conn.screen_height = FS_W, FS_H
    for atom, name in ((300, "_NET_WM_STATE"), (301, "_NET_WM_STATE_FULLSCREEN"),
                       (302, "_NET_WM_STATE_MAXIMIZED_VERT")):
        conn.profile.note_atom(atom, name)
    return conn


def create_window(window, parent, w, h, override=None):
    # ...x, y, w, h, border, class(1=InputOutput), visual, value-mask[, override]
    if override is None:
        return struct.pack(LE + "IIhhHHHHII", window, parent, 0, 0, w, h, 0, 1, 0, 0)
    return struct.pack(LE + "IIhhHHHHIII", window, parent, 0, 0, w, h, 0, 1, 0,
                       0x200, override)


def test_fullscreen_override_redirect_window_is_gated():
    conn = fs_connection()
    # override-redirect + fullscreen -> gated; the deny form strips override-redirect
    verdict, _ = conn.judge(1, 0, create_window(OWN, ROOT, FS_W, FS_H, override=1))
    assert isinstance(verdict, tuple) and verdict[0] == "fullscreen"
    assert struct.unpack_from(LE + "I", verdict[1], 28)[0] == 0, "override-redirect zeroed"
    # a small override-redirect window (a menu/tooltip) is untouched
    assert conn.judge(1, 0, create_window(BASE | 0x22, ROOT, SMALL_W, SMALL_H,
                                          override=1))[0] == "allow"
    # a fullscreen *managed* window (no override-redirect) is fine -- the WM frames it
    assert conn.judge(1, 0, create_window(BASE | 0x33, ROOT, FS_W, FS_H))[0] == "allow"


def test_fullscreen_by_resizing_an_override_redirect_window_is_caught():
    conn = fs_connection()
    # create small override-redirect (allowed, tracked), then grow to fullscreen
    assert conn.judge(1, 0, create_window(OWN, ROOT, SMALL_W, SMALL_H,
                                          override=1))[0] == "allow"
    def configure(window, w, h):
        return struct.pack(LE + "IHxxII", window, 0x4 | 0x8, w, h)  # CWWidth|CWHeight
    verdict, _ = conn.judge(12, 0, configure(OWN, FS_W, FS_H))
    assert isinstance(verdict, tuple) and verdict[0] == "fullscreen"
    assert verdict[1] is None, "the resize is dropped, not rewritten"


def test_fullscreen_by_setting_override_redirect_after_the_fact_is_caught():
    conn = fs_connection()
    # a fullscreen managed window (fine), then made override-redirect -> gated
    assert conn.judge(1, 0, create_window(OWN, ROOT, FS_W, FS_H))[0] == "allow"
    change = struct.pack(LE + "III", OWN, 0x200, 1)   # CWOverrideRedirect = True
    verdict, _ = conn.judge(2, 0, change)
    assert isinstance(verdict, tuple) and verdict[0] == "fullscreen"
    assert struct.unpack_from(LE + "I", verdict[1], 8)[0] == 0, "override-redirect zeroed"


def second_connection(first):
    """Another connection of the same application: same profile, same id range.

    Every toolkit opens several (an IDE was profiled at thirteen), and
    is_foreign() has always answered from the profile, so windows made on one
    are not foreign to the next.
    """
    conn = xfilter.PolicyConnection(None, None, None, None, first.profile,
                                    enforce=True)
    conn.endian = LE
    conn.id_base, conn.id_mask = BASE, MASK
    conn.gate_mode = first.gate_mode
    conn.alert_new = False
    conn.root, conn.roots = first.root, set(first.roots)
    conn.screen_width, conn.screen_height = first.screen_width, first.screen_height
    conn.extension_opcodes = dict(first.extension_opcodes)
    return conn


def test_the_window_model_is_shared_by_the_applications_connections():
    # Twelfth pass.  The model of own windows used to live on the connection
    # that made them, so doing the two halves of an operation on two
    # connections walked around both protections that read it.  Measured live:
    # connection B read the true global pointer position through connection A's
    # window, and resized A's small override-redirect window to cover the
    # screen with no gate firing.
    a = fs_connection()
    b = second_connection(a)

    # A creates and maps a small window; B asks where the pointer is over it
    assert a.judge(1, 0, create_window(OWN, ROOT, SMALL_W, SMALL_H))[0] == "allow"
    assert a.judge(8, 0, struct.pack(LE + "I", OWN))[0] == "allow"   # MapWindow
    for conn, who in ((a, "the connection that made it"),
                      (b, "another connection of the same application")):
        assert conn.judge(38, 0, struct.pack(LE + "I", OWN))[0] \
            == ("pointer", ((SMALL_W, SMALL_H), "core")), who

    # A creates a menu-sized override-redirect window; B resizes it fullscreen
    menu = BASE | 0x44
    assert a.judge(1, 0, create_window(menu, ROOT, SMALL_W, SMALL_H,
                                       override=1))[0] == "allow"
    configure = struct.pack(LE + "IHxxII", menu, 0x4 | 0x8, FS_W, FS_H)
    verdict, _ = b.judge(12, 0, configure)
    assert isinstance(verdict, tuple) and verdict[0] == "fullscreen", \
        "the overlay is gated whichever connection assembles it"
    assert verdict[1] is None, "the resize is dropped"


def test_the_window_model_forgets_what_the_server_frees():
    # Twelfth pass.  The model never forgot: a create/destroy loop grew it for
    # the life of the connection while the server's own memory stayed flat, and
    # a reused id kept the size of the window that used to hold it.
    conn = fs_connection()
    parent, child = OWN, BASE | 0x55
    assert conn.judge(1, 0, create_window(parent, ROOT, SMALL_W, SMALL_H))[0] \
        == "allow"
    assert conn.judge(1, 0, create_window(child, parent, 10, 10))[0] == "allow"
    assert conn.profile.window_state(child) is not None

    assert conn.judge(4, 0, struct.pack(LE + "I", parent))[0] == "allow"
    assert conn.profile.window_state(parent) is None, "the window is forgotten"
    assert conn.profile.window_state(child) is None, \
        "and so is everything the server destroyed with it"
    assert conn.profile.windows == {} and not any(conn.profile.children.values())

    # DestroySubwindows takes the children and leaves the parent
    assert conn.judge(1, 0, create_window(parent, ROOT, SMALL_W, SMALL_H))[0] \
        == "allow"
    assert conn.judge(1, 0, create_window(child, parent, 10, 10))[0] == "allow"
    assert conn.judge(5, 0, struct.pack(LE + "I", parent))[0] == "allow"
    assert conn.profile.window_state(child) is None
    assert conn.profile.window_state(parent) is not None

    # unmapping puts the window out of reach of the pointer bound again
    assert conn.judge(8, 0, struct.pack(LE + "I", parent))[0] == "allow"
    assert conn.judge(38, 0, struct.pack(LE + "I", parent))[0][1][0] is not None
    assert conn.judge(10, 0, struct.pack(LE + "I", parent))[0] == "allow"
    assert conn.judge(38, 0, struct.pack(LE + "I", parent))[0][1][0] is None


def test_a_selection_is_converted_into_the_clients_own_window():
    # Fourteenth pass.  The requestor field of ConvertSelection names the
    # window the *owner* writes its answer into, and nothing checked it.  Two
    # things came of that, both measured: under the default --gate deny, a
    # write the policy refuses outright went through when the client asked a
    # trusted selection owner to do it instead (the third application's window
    # held the owner's data under a property name the untrusted client chose);
    # and when the client owns the selection, the *server* then hands it a
    # genuine SelectionRequest naming any window it likes, which is what EV-7
    # trusts to grant foreign property writes.
    conn = make_connection(gate_mode="allow")
    def convert(requestor, selection):
        return struct.pack(LE + "IIIII", requestor, selection, 31, 200, 0)
    assert conn.judge(24, 0, convert(FOREIGN, 100))[0] == "silent", \
        "a selection may not be converted into somebody else's window"
    assert conn.judge(24, 0, convert(FOREIGN, 999))[0] == "silent", \
        "including a selection the gate does not cover -- that was the "\
        "route that needed no user approval at all"
    assert conn.judge(24, 0, convert(OWN, 999))[0] == "allow", \
        "converting into your own window is what every toolkit does"
    assert conn.judge(24, 0, convert(OWN, 100))[0] == "allow"


def test_a_selection_grant_is_an_answer_not_a_standing_permission():
    # Fourteenth pass.  The grants EV-7 records -- may write this property on
    # that window, may send it a SelectionNotify -- never expired, and the
    # second one also exempts the window from the EV-3 rule that withholds
    # PropertyNotify for a property the client may not read.  So one copy-out
    # bought a permanent property-change monitor on the window that asked.
    conn = rooted_connection()
    conn.grant_selection(FOREIGN, 105)
    write = struct.pack(LE + "IIIBBxxI", FOREIGN, 105, 31, 8, 0, 1) + b"\0" * 4
    assert conn.judge(18, 0, write)[0] == "allow", "the answer may be written"

    def property_notify(window, atom):
        event = bytearray(32)
        event[0] = 28
        struct.pack_into(LE + "II", event, 4, window, atom)
        return bytes(event)

    conn.profile.note_atom(102, "WM_NAME")
    assert conn.patch_event(property_notify(FOREIGN, 102)) is None, \
        "during the transfer, the requestor's property traffic reaches us"

    # the same two, once the grant has aged out
    for table in (conn.selection_requests, conn.selection_requestors):
        for key in table:
            table[key] = time.time() - 1
    assert conn.judge(18, 0, write)[0] == "silent", \
        "afterwards it is somebody else's window again"
    assert conn.patch_event(property_notify(FOREIGN, 102)) is conn.DROP_EVENT, \
        "and the EV-3 channel closes with it"
    assert conn.granted(conn.selection_requestors, FOREIGN) is False


def test_the_policy_resolves_its_own_atoms_rather_than_waiting_to_be_told():
    # Thirteenth pass.  Every rule here is written in names and the wire
    # carries numbers, and the mapping used to be a by-product of the client's
    # own InternAtom traffic.  A client that came by an id another way -- the
    # ids are listed in _NET_SUPPORTED on the root, which the policy allows it
    # to read -- met rules that could not recognise what they were looking at.
    # Measured against openbox: a 300x200 window that set _NET_WM_STATE by id
    # went fullscreen through the proxy, and the same request with the name
    # interned was refused.
    assert "_NET_WM_STATE" in xfilter.POLICY_ATOMS
    assert "_NET_WM_STATE_FULLSCREEN" in xfilter.POLICY_ATOMS
    assert xfilter.FOREIGN_PROPERTY_ALLOW <= xfilter.POLICY_ATOMS, \
        "an allowlist entry the proxy cannot name is an entry that never admits"
    assert xfilter.EWMH_MESSAGES <= xfilter.POLICY_ATOMS
    assert xfilter.EWMH_WINDOW_TARGETS <= xfilter.POLICY_ATOMS

    # main() seeds the profile with those names before any client connects, so
    # the gate fires on an id this connection never interned
    conn = fs_connection()
    unnamed_state, unnamed_full = 900, 901
    def state_property(prop, value):          # ChangeProperty on our own window
        return struct.pack(LE + "IIIBBxxI", OWN, prop, 4, 32, 0, 1) \
            + struct.pack(LE + "I", value)
    assert conn.judge(18, 0, state_property(unnamed_state, unnamed_full))[0] \
        == "allow", "with no name for the atom, nothing can fire"
    conn.profile.note_atom(unnamed_state, "_NET_WM_STATE")
    conn.profile.note_atom(unnamed_full, "_NET_WM_STATE_FULLSCREEN")
    verdict, _ = conn.judge(18, 0, state_property(unnamed_state, unnamed_full))
    assert isinstance(verdict, tuple) and verdict[0] == "fullscreen", \
        "seeded at startup, the gate fires on the id alone"

    # and the same seeding is what lets an ordinary read be *admitted* by id
    supported = 902
    read = struct.pack(LE + "IIIII", FOREIGN, supported, 4, 0, 1024)
    assert callable(conn.judge(20, 0, read)[0]), "unnamed: refused"
    conn.profile.note_atom(supported, "_NET_SUPPORTED")
    assert conn.judge(20, 0, read)[0] == "allow", "named: admitted"


def test_the_event_filter_does_not_wait_for_a_polite_client():
    # Thirteenth pass.  patch_event recognises an XKB event by the event base
    # the server assigned XKEYBOARD, and that base was learned only from a
    # QueryExtension reply -- a question the client can simply not ask, while
    # still using the extension through its stable major opcode, which is the
    # very trick the opcode learning exists to defeat.  Measured: subtypes 2
    # (modifier state, ninth pass) and 4 (lock state, eleventh) arriving
    # through the proxy exactly as they do direct.
    conn = rooted_connection()

    def xkb_event(subtype):
        event = bytearray(32)
        event[0] = 85
        event[1] = subtype
        return bytes(event)

    assert conn.patch_event(xkb_event(2)) is None, \
        "with no base learned, an XKB event is not even recognised"
    # main() now seeds this from its own startup QueryExtension, not the
    # client's, so the filter runs for a client that never asked
    conn.profile.note_extension(135, "XKEYBOARD", first_event=85)
    assert conn.patch_event(xkb_event(2)) is conn.DROP_EVENT
    assert conn.patch_event(xkb_event(4)) is conn.DROP_EVENT
    assert conn.patch_event(xkb_event(0)) is None


def test_dry_run_changes_nothing_in_the_event_stream():
    # --dry-run reports what the policy would refuse and refuses nothing, and
    # the request and reply paths keep that promise -- a substitution is only
    # registered `if self.enforce`.  The event path did not, so a profiling run
    # silently differed from an unfiltered one.  Found by the attack suite's
    # own self-test: with enforcement off every check must go red, and this one
    # stayed green.
    conn = make_connection(enforce=False)
    conn.root, conn.roots = ROOT, {ROOT}
    conn.profile.note_extension(135, "XKEYBOARD", first_event=85)
    conn.profile.note_atom(102, "WM_NAME")

    state_notify = bytearray(32); state_notify[0] = 85; state_notify[1] = 2
    keymap = bytearray(32); keymap[0] = 11; keymap[9] = 0xFF
    property_notify = bytearray(32)
    property_notify[0] = 28
    struct.pack_into(LE + "II", property_notify, 4, FOREIGN, 102)

    for event in (state_notify, keymap, property_notify):
        assert conn.patch_event(bytes(event)) is None, \
            "dry run watches; it does not withhold or rewrite"

    # ...but it still learns, so the report it prints is about the real traffic
    request = bytearray(32)
    request[0] = 30                                   # SelectionRequest
    struct.pack_into(LE + "I", request, 12, FOREIGN)
    struct.pack_into(LE + "I", request, 24, 105)
    conn.patch_event(bytes(request))
    assert conn.granted(conn.selection_requestors, FOREIGN), \
        "the grant is still recorded, so the dry run reports what would happen"

    # the enforcing connection is unchanged
    enforcing = rooted_connection()
    enforcing.profile.note_extension(135, "XKEYBOARD", first_event=85)
    assert enforcing.patch_event(bytes(state_notify)) is enforcing.DROP_EVENT


def test_a_client_cannot_forge_a_line_of_the_operation_log():
    # Twelfth pass.  describe() is the client's own testimony about itself, and
    # it is printed to the operator's terminal, appended to the --log file and
    # shown in the gate prompt.  Measured before the fix: a WM_CLASS with a
    # newline in it put a complete, plausible, false line in the log -- three
    # times -- claiming a trusted application had been allowed a screen capture.
    conn = make_connection()
    conn.profile.note_atom(400, "WM_CLASS")
    forged = ("xterm\nnew operation: core:GetImage    allowed  trusted "
              "desktop app [local pid 1, uid 0]\x1b[31m" + "A" * 300)
    value = forged.encode("latin-1") + b"\0"
    conn.note_identity(struct.pack(LE + "IIIBBxxI", OWN, 400, 31, 8, 0,
                                   len(value)) + value)
    label = conn.describe()
    assert "\n" not in label, "a name cannot start a new line of the log"
    assert "\x1b" not in label, "nor issue an instruction to the terminal"
    assert len(label) <= core.LABEL_LIMIT + 3, \
        "nor push the real lines off the screen with padding"
    assert label.startswith("xterm?new operation"), \
        "what the client called itself is still shown, as one line of text"
    # the stored testimony is untouched: cleaning happens on the way out, and
    # a name sanitised before it is *matched* would be a way to pass as another
    assert conn.identity["class"] == forged


def test_a_failed_request_releases_what_was_held_for_its_reply():
    # Twelfth pass.  Only replies reached substitution(), so a request that
    # ended in an error left its entry behind: memory a client could grow in a
    # loop (a pointer query naming a window it has just destroyed), and -- since
    # the key is a 16-bit sequence number -- a mine that goes off 65,536
    # requests later, applied to somebody else's reply.
    conn = rooted_connection()
    conn.substitutions[7] = lambda seq: b""
    conn.reply_scrubs[7] = [(8, 4)]
    conn.reply_foreign[7] = ([8], 0)
    conn.reply_pointer[7] = ((10, 10), "core")
    conn.reply_leds.add(7)
    conn.query_denied[7] = True
    conn.listings.add(7)

    conn.discard_sequence(7)

    assert not conn.substitutions and not conn.reply_scrubs
    assert not conn.reply_foreign and not conn.reply_pointer
    assert not conn.reply_leds and not conn.query_denied and not conn.listings
    conn.discard_sequence(7)          # a second error for the same sequence


def grab_keyboard(window):
    # owner-events is the header's data byte; the body is the grab window, the
    # timestamp and the two modes
    return struct.pack(LE + "IIBBxx", window, 0, 1, 1)


def test_a_keyboard_grab_is_allowed_and_its_keystrokes_are_bounded():
    # Twentieth pass, revised by measurement.  A client may grab the keyboard
    # on a window of its own, and while the grab is held the server delivers
    # every keystroke to it, whatever the user believes they are typing into.
    # Refusing the grab was tried and cost too much: GTK asks for the pointer
    # and the keyboard in one request, so a refusal stopped context menus
    # opening at all (measured against gedit, which opened one at the pointer
    # without the proxy and none through it).  So the grab is allowed and the
    # delivery is bounded instead -- the same shape as the pointer grab.
    conn = make_connection()
    assert conn.judge(31, 0, grab_keyboard(OWN))[0] == "allow", \
        "menus need this, and what it would steal is withheld elsewhere"
    assert conn.judge(26, 0, struct.pack(LE + "IHBBIII", OWN, 0, 1, 1, 0, 0,
                                         0))[0] == "allow", "so does drag"
    # a foreign window was refused before this pass and still is
    assert callable(conn.judge(31, 0, grab_keyboard(FOREIGN))[0])
    assert callable(conn.judge(26, 0, struct.pack(LE + "IHBBIII", FOREIGN, 0,
                                                  1, 1, 0, 0, 0))[0])


def xi_grab_device(window, mask):
    # window, time, cursor, deviceid, mode, paired mode, owner-events, pad,
    # mask length in words, then the mask
    return struct.pack(LE + "IIIHBBBxHI", window, 0, 0, 3, 1, 1, 0, 1, mask)


def test_the_xinput_grab_is_the_same_keylogger_as_the_core_one():
    # Twentieth pass, second half.  GTK and Qt grab through XInput2, so the
    # XI2 spelling has to be treated exactly like the core one -- allowed, and
    # bounded by the same delivery rule.
    conn = make_connection()
    conn.extension_opcodes = {131: "XInputExtension"}
    keys = (1 << 2) | (1 << 3)                    # XI_KeyPress, XI_KeyRelease
    assert conn.judge(131, 51, xi_grab_device(OWN, keys))[0] == "allow", \
        "this is the request GTK opens every menu with"
    assert conn.judge(131, 13, struct.pack(LE + "I", OWN))[0] == "allow"
    # ...and both are still refused on somebody else's window
    assert callable(conn.judge(131, 51, xi_grab_device(FOREIGN, keys))[0])
    assert callable(conn.judge(131, 13, struct.pack(LE + "I", FOREIGN))[0])


def _xi_motion(conn, window, event_x, event_y, root_x=700, root_y=500):
    head = bytearray(32)
    head[0] = 35                                  # generic event
    head[1] = 131                                 # XInputExtension
    struct.pack_into(LE + "H", head, 8, 6)        # XI_Motion
    struct.pack_into(LE + "II", head, 24, window, 0x999)
    body = bytearray(48)
    struct.pack_into(LE + "iiii", body, 0, root_x << 16, root_y << 16,
                     event_x << 16, event_y << 16)
    for offset in range(24, 40, 4):
        struct.pack_into(LE + "I", body, offset, 0x1F)      # modifiers
    return bytes(head), bytes(body)


def test_an_xinput_event_from_outside_our_window_carries_no_position():
    # The generic-event twin of the core bound.  The tenth pass left this
    # channel pass-or-drop on the grounds that an XGE's layout belongs to its
    # extension -- true in general, and not of XI2's device events, whose
    # shape the pointer bound already relies on for XIQueryPointer's reply.
    conn = rooted_connection()
    conn.extension_opcodes = {131: "XInputExtension"}
    track_window(conn, OWN, 200, 100)

    head, body = _xi_motion(conn, OWN, 50, 40)
    assert conn.patch_generic_event(head, body) is None, \
        "over its own window the client may have the position"

    head, body = _xi_motion(conn, OWN, 50, 400)
    patched = conn.patch_generic_event(head, body)
    assert patched is not None and patched is not conn.DROP_EVENT
    new_head, new_body = patched
    assert struct.unpack_from(LE + "ii", new_body, 0) == (0, 0), \
        "elsewhere on the desktop, the root position is withheld"
    assert struct.unpack_from(LE + "I", new_head, 28)[0] == 0, "and the child"
    assert struct.unpack_from(LE + "I", new_body, 24)[0] == 0, "and the modifiers"
    assert struct.unpack_from(LE + "ii", new_body, 8) \
        == (50 << 16, 400 << 16), "the window-relative position is untouched"


def _key_event(code=2):
    event = bytearray(32)
    event[0] = code
    return bytes(event)


def test_a_key_event_arrives_only_while_we_hold_the_focus():
    # Twentieth pass, third form.  Gating the grab cost too much (GTK menus
    # stopped opening), so the grab is allowed and the *delivery* is bounded:
    # a key event reaches the client only while a window of its own has the
    # focus.  A menu belongs to an application the user is working in; a
    # client watching from the background is not, and gets nothing.
    conn = rooted_connection()
    answers = []
    conn_focus = lambda endian="<": answers.pop(0)
    saved = xfilter.focus_window
    xfilter.focus_window = conn_focus
    try:
        answers[:] = [OWN]
        assert conn.patch_event(_key_event()) is None, "our window: delivered"
        answers[:] = [ROOT]
        assert conn.patch_event(_key_event()) is None, "the root is nobody's"
        answers[:] = [1]
        assert conn.patch_event(_key_event()) is None, "PointerRoot: delivered"
        answers[:] = [FOREIGN]
        assert conn.patch_event(_key_event()) is conn.DROP_EVENT, \
            "somebody else is being typed into"
        answers[:] = [0]
        assert conn.patch_event(_key_event()) is conn.DROP_EVENT, \
            "nobody holds the focus, so this key is nobody's -- and is_foreign "\
            "reads 0 as None, which had this answering 'ours'"
        answers[:] = [None]
        assert conn.patch_event(_key_event()) is None, \
            "no way to ask: do not make the client deaf"
        for code in (2, 3):
            answers[:] = [FOREIGN]
            assert conn.patch_event(_key_event(code)) is conn.DROP_EVENT, code
    finally:
        xfilter.focus_window = saved


def _motion_event(window, event_x, event_y, root_x=700, root_y=500):
    event = bytearray(32)
    event[0] = 6                                        # MotionNotify
    struct.pack_into(LE + "III", event, 8, ROOT, window, 0x999)
    struct.pack_into(LE + "hhhh", event, 20, root_x, root_y, event_x, event_y)
    struct.pack_into(LE + "H", event, 28, 0x1F)         # modifier state
    return bytes(event)


def test_a_pointer_event_from_outside_our_window_carries_no_position():
    # Twentieth pass.  A pointer grab on the client's own window makes the
    # server report every motion, button and crossing event to it, wherever the
    # pointer is -- the whole-desktop trace three earlier passes closed by
    # other roads (measured: (200,150), (700,500), (1100,800) through the
    # proxy).  The grab stays allowed, because menus and drag-and-drop need it;
    # the position is bounded by the same test the reply side uses.
    conn = rooted_connection()
    track_window(conn, OWN, 200, 100)

    inside = conn.patch_event(_motion_event(OWN, 50, 40))
    assert inside is None, "over its own window, the client may have the position"

    outside = conn.patch_event(_motion_event(OWN, 50, 400))
    assert outside is not None
    assert struct.unpack_from(LE + "hh", outside, 20) == (0, 0), \
        "elsewhere on the desktop, the global position is withheld"
    assert struct.unpack_from(LE + "I", outside, 16)[0] == 0, "and the child"
    assert struct.unpack_from(LE + "H", outside, 28)[0] == 0, \
        "and the modifiers, which are not ours to read off somebody else's work"

    # an untracked or unmapped window proves nothing, so it is bounded too
    unmapped = BASE | 0x81
    conn.profile.note_window(unmapped, ROOT, 200, 100, False)
    assert conn.patch_event(_motion_event(unmapped, 10, 10)) is not None
    assert conn.patch_event(_motion_event(FOREIGN, 10, 10)) is not None

    # every event that carries the position is covered, not just motion
    for code in (4, 5, 7, 8):                # button press/release, enter/leave
        event = bytearray(_motion_event(OWN, 50, 400))
        event[0] = code
        assert conn.patch_event(bytes(event)) is not None, code


def test_every_screen_is_measured_against_itself():
    # Twenty-first pass.  The spoof gate compared every window with the *first*
    # screen's size, so a borderless window covering a second, smaller screen
    # was fullscreen by no measure the policy took.  Measured on a two-screen
    # server: 640x480 over the whole of screen 1 kept its override-redirect,
    # while the same trick on screen 0 was stripped.  A laptop with a projector
    # is the ordinary case here.
    conn = fs_connection()
    second_root = ROOT + 2
    conn.roots = {ROOT, second_root}
    conn.screen_size = {ROOT: (FS_W, FS_H), second_root: (640, 480)}

    # the small screen, covered entirely
    verdict, _ = conn.judge(1, 0, create_window(OWN, second_root, 640, 480,
                                                override=1))
    assert isinstance(verdict, tuple) and verdict[0] == "fullscreen", \
        "a window covering the second screen is a fake desktop on it"

    # the same size on the big screen is an ordinary window
    assert conn.judge(1, 0, create_window(BASE | 0x91, ROOT, 640, 480,
                                          override=1))[0] == "allow"

    # and the tiling rule counts each screen separately
    quiet = fs_connection()
    quiet.roots = {ROOT, second_root}
    quiet.screen_size = {ROOT: (FS_W, FS_H), second_root: (640, 480)}
    tiles = []
    for index in range(2):
        window = BASE | (0xA0 + index)
        assert quiet.judge(1, 0, create_window(window, second_root, 320, 480,
                                               override=1))[0] == "allow"
        tiles.append(window)
    verdicts = [quiet.judge(8, 0, struct.pack(LE + "I", w))[0] for w in tiles]
    assert any(isinstance(v, tuple) and v[0] == "fullscreen" for v in verdicts), \
        "two tiles covering the second screen are gated there too"


def test_a_fake_desktop_cannot_be_assembled_out_of_tiles():
    # Nineteenth pass.  The gate asked whether *a* window covered the screen,
    # so a fake desktop that is four windows walked past it: measured through
    # the proxy with a window manager running, four override-redirect windows
    # of half the screen's width and height each turned all four quadrants of
    # the real screen the attacker's colour, logged only as CreateWindow and
    # MapWindow allowed.
    conn = fs_connection()
    half_w, half_h = FS_W // 2, FS_H // 2
    tiles = []
    for index in range(4):
        window = BASE | (0x60 + index)
        assert conn.judge(1, 0, create_window(window, ROOT, half_w, half_h,
                                              override=1))[0] == "allow", \
            "a window of a quarter of the screen is not a fake desktop"
        tiles.append(window)

    mapped = 0
    for window in tiles:
        verdict = conn.judge(8, 0, struct.pack(LE + "I", window))[0]
        if isinstance(verdict, tuple) and verdict[0] == "fullscreen":
            break
        assert verdict == "allow"
        mapped += 1
    assert mapped < len(tiles), "the last tile completes the covering and is gated"

    # what is left is no more than one window is already allowed to cover, so
    # splitting buys the attacker nothing
    covered = mapped * half_w * half_h
    one_window = int(FS_W * xfilter.FULLSCREEN_FRACTION) \
        * int(FS_H * xfilter.FULLSCREEN_FRACTION)
    assert covered <= one_window, \
        "tiles must not cover more than a single allowed window could"

    # and an ordinary menu is untouched
    quiet = fs_connection()
    menu = BASE | 0x70
    assert quiet.judge(1, 0, create_window(menu, ROOT, SMALL_W, SMALL_H,
                                           override=1))[0] == "allow"
    assert quiet.judge(8, 0, struct.pack(LE + "I", menu))[0] == "allow"


def test_ewmh_fullscreen_clientmessage_is_gated():
    conn = fs_connection()
    def msg(action, atom1, atom2=0):
        ev = bytearray(32)
        ev[0] = 33                                    # ClientMessage
        struct.pack_into(LE + "I", ev, 8, 300)        # type _NET_WM_STATE
        struct.pack_into(LE + "I", ev, 12, action)
        struct.pack_into(LE + "I", ev, 16, atom1)
        struct.pack_into(LE + "I", ev, 20, atom2)
        return struct.pack(LE + "II", ROOT, 0) + bytes(ev)
    assert conn.judge(25, 0, msg(1, 301))[0][0] == "fullscreen"   # add fullscreen
    assert conn.judge(25, 0, msg(2, 301))[0][0] == "fullscreen"   # toggle fullscreen
    assert conn.judge(25, 0, msg(0, 301))[0] == "allow"           # remove fullscreen
    assert conn.judge(25, 0, msg(1, 302))[0] == "allow"           # a different state


def test_ewmh_fullscreen_property_is_stripped_and_others_kept():
    conn = fs_connection()
    body = struct.pack(LE + "IIIBxxxI", OWN, 300, 4, 32, 2) \
        + struct.pack(LE + "II", 302, 301)            # [MAXIMIZED, FULLSCREEN]
    verdict, _ = conn.judge(18, 0, body)
    assert isinstance(verdict, tuple) and verdict[0] == "fullscreen"
    assert struct.unpack_from(LE + "I", verdict[1], 20)[0] == 302, "maximize kept"
    assert struct.unpack_from(LE + "I", verdict[1], 24)[0] == 0, "fullscreen zeroed"
    # a _NET_WM_STATE without fullscreen is left alone
    only_max = struct.pack(LE + "IIIBxxxI", OWN, 300, 4, 32, 1) + struct.pack(LE + "I", 302)
    assert conn.judge(18, 0, only_max)[0] == "allow"


def test_fullscreen_gate_modes():
    # deny (default) refuses, allow permits, ask with no prompt falls back to deny
    conn = rooted_connection()
    conn.gate_mode = "deny"
    assert conn._fullscreen_allowed() is False
    conn.gate_mode = "allow"
    assert conn._fullscreen_allowed() is True
    conn.gate_mode = "ask"                            # gate object is None here
    assert conn._fullscreen_allowed() is False


# -- ninth pass: closing the activity-silhouette residuals ------------------

def test_active_window_read_is_refused_like_the_focus_query():
    # _NET_ACTIVE_WINDOW names whichever window the user is in, on the root, so
    # polling it is the focus trace GetInputFocus (OF-1) and the XInput focus
    # reads (XI-1) withhold one request at a time.  It was on
    # FOREIGN_PROPERTY_ALLOW; removed, the read is answered blank on a foreign
    # window (the root included), while the properties a client legitimately
    # reads off the root still pass.
    conn = rooted_connection()
    conn.profile.note_atom(400, "_NET_ACTIVE_WINDOW")
    conn.profile.note_atom(401, "_NET_SUPPORTED")
    conn.profile.note_atom(402, "_NET_CLIENT_LIST")
    # foreign/root read of the active window is now blanked
    assert callable(conn.judge(20, 0, get_property(ROOT, 400))[0]), \
        "the active-window poll is closed"
    assert callable(conn.judge(20, 0, get_property(FOREIGN, 400))[0])
    # a property the client is still allowed to read off the root passes
    assert conn.judge(20, 0, get_property(ROOT, 401))[0] == "allow", \
        "theming/negotiation reads are untouched"
    # _NET_CLIENT_LIST -- the root's list of every top-level window -- is
    # refused too: one read otherwise hands a remote client every foreign
    # window id, the enumeration the foreign-window attacks relied on.
    assert callable(conn.judge(20, 0, get_property(ROOT, 402))[0]), \
        "the whole-desktop window enumeration is closed"
    assert callable(conn.judge(20, 0, get_property(FOREIGN, 402))[0])
    # its own active-window-atom property, if it ever set one, is its own
    assert conn.judge(20, 0, get_property(OWN, 400))[0] == "allow"


def test_active_window_property_notify_is_now_a_real_closure():
    # With the read refused, dropping the PropertyNotify for it stops being
    # theatre (EV-3): a client that cannot read the value cannot poll it
    # either, so the timing channel closes with no polling equivalent left.
    conn = rooted_connection()
    conn.profile.note_atom(400, "_NET_ACTIVE_WINDOW")
    assert conn.patch_event(property_notify(ROOT, 400)) is conn.DROP_EVENT, \
        "the active-window change on the root is withheld now the read is gone"


def test_xkb_get_state_modifier_poll_is_blanked():
    # EV-6.  XkbGetState (minor 4) returns the live modifier/group/pointer-button
    # state of the shared keyboard; poll it and it is the modifier logger
    # QueryKeymap already answers empty.  The state fields (offset 8 through the
    # ptrBtnState at 24-25) are blanked; device id, sequence and length stay.
    conn = make_connection()
    conn.extension_opcodes = {135: "XKEYBOARD"}
    verdict, _ = conn.judge(135, 4, b"\0" * 8)
    assert verdict == ("scrub", [(8, 18)]), verdict
    # the scrub, applied to a reply full of state, leaves only the framing
    head = bytearray(8)
    head[0] = 1; head[1] = 3                          # reply, deviceID 3
    struct.pack_into(LE + "H", head, 2, 77)           # sequence
    reply_body = bytes(range(1, 25))                  # 24 bytes of "state"
    scrubbed = conn.scrub_reply(bytes(head), reply_body, [(8, 18)])
    assert scrubbed[1] == 3, "device id kept"
    assert struct.unpack_from(LE + "H", scrubbed, 2)[0] == 77, "sequence kept"
    assert all(b == 0 for b in scrubbed[8:26]), "all modifier/group state blanked"


def test_xkb_state_notify_event_is_withheld():
    # EV-6 event side.  XKEYBOARD delivers every event under one type byte with
    # the subtype in the second; XkbStateNotify (subtype 2) carries the same
    # shared state XkbGetState is blanked for.  Drop it, but let the two events
    # toolkits need -- XkbNewKeyboardNotify (0), XkbMapNotify (1) -- pass.
    conn = rooted_connection()
    conn.profile.note_extension(135, "XKEYBOARD", first_event=85)

    def xkb_event(subtype):
        event = bytearray(32)
        event[0] = 85
        event[1] = subtype
        return bytes(event)

    assert conn.patch_event(xkb_event(2)) is conn.DROP_EVENT, "StateNotify withheld"
    assert conn.patch_event(xkb_event(0)) is None, "NewKeyboardNotify passes"
    assert conn.patch_event(xkb_event(1)) is None, "MapNotify passes"
    # a server that never advertised XKB events must not have its core events
    # misread as XKB ones
    bare = rooted_connection()
    other = bytearray(32); other[0] = 85; other[1] = 2
    assert bare.patch_event(bytes(other)) is None, \
        "with no XKB base learned, type 85 is not treated as XkbStateNotify"


def _core_pointer_reply(root_x, root_y, win_x, win_y, same_screen=1,
                        child=0x123, mask=0xFFFF):
    # a 32-byte core QueryPointer reply
    buf = bytearray(32)
    buf[0] = 1
    buf[1] = same_screen
    struct.pack_into(LE + "II", buf, 8, ROOT, child)
    struct.pack_into(LE + "hhhh", buf, 16, root_x, root_y, win_x, win_y)
    struct.pack_into(LE + "H", buf, 24, mask)
    return bytes(buf[:8]), bytes(buf[8:])


def test_query_pointer_is_bounded_to_the_clients_own_window():
    # The reply carries the global pointer position even when the pointer is
    # over another window, so polling QueryPointer over a window the client owns
    # traces the pointer across the whole screen.  bound_pointer_reply keeps the
    # position only when the reply proves the pointer is over this window.
    conn = rooted_connection()
    # judge bounds against the *shared* model: a window this application
    # created, and mapped -- an unmapped one is a measuring stick, not a window
    track_window(conn, OWN, 200, 100)
    verdict, _ = conn.judge(38, 0, struct.pack(LE + "I", OWN))
    assert verdict == ("pointer", ((200, 100), "core")), verdict

    # pointer inside the 200x100 window: position kept, only the mask blanked
    head, body = _core_pointer_reply(1500, 1500, 50, 40)
    kept = conn.bound_pointer_reply(head, body, (200, 100), "core")
    assert struct.unpack_from(LE + "hh", kept, 16) == (1500, 1500), \
        "position over the client's own window is legitimate"
    assert struct.unpack_from(LE + "H", kept, 24)[0] == 0, "mask always blanked"
    assert kept[1] == 1, "same_screen kept when inside"

    # pointer outside the window (win_y past the height): position blanked
    head, body = _core_pointer_reply(1500, 1500, 50, 400)
    gone = conn.bound_pointer_reply(head, body, (200, 100), "core")
    assert struct.unpack_from(LE + "hh", gone, 16) == (0, 0), \
        "the global position is withheld when the pointer is elsewhere"
    assert struct.unpack_from(LE + "hh", gone, 20) == (0, 0), "win coords too"
    assert gone[1] == 0 and struct.unpack_from(LE + "I", gone, 12)[0] == 0, \
        "same_screen and child blanked when the pointer is not over us"

    # not-same-screen counts as outside even if the coords look in range
    head, body = _core_pointer_reply(1500, 1500, 50, 40, same_screen=0)
    off = conn.bound_pointer_reply(head, body, (200, 100), "core")
    assert struct.unpack_from(LE + "hh", off, 16) == (0, 0), \
        "another screen is not this window"

    # Twelfth pass.  An untracked window proves nothing, and unproven now
    # blanks: the root is untracked, and QueryPointer(root) -- how every
    # toolkit asks where the mouse is -- used to walk straight past the bound.
    head, body = _core_pointer_reply(1500, 1500, 9999, 9999)
    unknown = conn.bound_pointer_reply(head, body, None, "core")
    assert struct.unpack_from(LE + "hh", unknown, 16) == (0, 0), \
        "unproven is blanked, not left intact"
    assert struct.unpack_from(LE + "H", unknown, 24)[0] == 0, "mask still blanked"
    assert conn.judge(38, 0, struct.pack(LE + "I", ROOT))[0] \
        == ("pointer", (None, "core")), "the root bounds to nothing"

    # ...and so does a window the client created but never mapped
    conn.profile.note_window(OWN + 4, ROOT, 1280, 900, False)
    assert conn.judge(38, 0, struct.pack(LE + "I", OWN + 4))[0] \
        == ("pointer", (None, "core")), "an unmapped window is not a place"
    conn.profile.note_mapped(OWN + 4, True)
    assert conn.judge(38, 0, struct.pack(LE + "I", OWN + 4))[0] \
        == ("pointer", ((1280, 900), "core")), "once mapped, it is one"


def test_xinput_query_pointer_is_bounded_too():
    # XIQueryPointer is the XInput twin, with FP1616 coordinates; the same
    # bounding applies and the input-state tail past offset 36 is always blanked.
    conn = rooted_connection()
    conn.extension_opcodes = {131: "XInputExtension"}
    track_window(conn, OWN, 200, 100)
    verdict, _ = conn.judge(131, 40, struct.pack(LE + "IHH", OWN, 0, 0))
    assert verdict == ("pointer", ((200, 100), "xi")), verdict

    def xi_reply(win_x, win_y, same_screen=1):
        buf = bytearray(56)
        buf[0] = 1
        struct.pack_into(LE + "II", buf, 8, ROOT, 0x123)         # root, child
        struct.pack_into(LE + "iiii", buf, 16,
                         1500 << 16, 1500 << 16, win_x << 16, win_y << 16)
        buf[32] = same_screen
        for i in range(36, 56):
            buf[i] = 0xAB                                        # input-state tail
        return bytes(buf[:8]), bytes(buf[8:])

    head, body = xi_reply(50, 40)
    kept = conn.bound_pointer_reply(head, body, (200, 100), "xi")
    assert struct.unpack_from(LE + "i", kept, 16)[0] >> 16 == 1500, "inside: kept"
    assert all(b == 0 for b in kept[36:]), "input-state tail always blanked"

    head, body = xi_reply(50, 400)
    gone = conn.bound_pointer_reply(head, body, (200, 100), "xi")
    assert struct.unpack_from(LE + "i", gone, 16)[0] == 0, "outside: root_x blanked"
    assert struct.unpack_from(LE + "i", gone, 24)[0] == 0, "win_x blanked"
    assert gone[32] == 0, "same_screen blanked"

# --- the xauth file, which the proxy now reads and writes itself ------------
#
# Captured from the real `xauth -f FILE add :77 MIT-MAGIC-COOKIE-1 <hex>`, so
# these tests pin our parser against the format the tool actually writes
# rather than against our own writer agreeing with itself.  That matters more
# than usual here: an X server reads this file to decide who may connect, and
# libXau in every client reads it to decide what to offer.
XAUTH_FROM_THE_REAL_TOOL = (
    b"\x01\x00"                                     # family 256, FamilyLocal
    b"\x00\x08poderosa"                             # address: the hostname
    b"\x00\x0277"                                   # display number
    b"\x00\x12MIT-MAGIC-COOKIE-1"                   # authorisation name
    b"\x00\x10" + bytes.fromhex("04b05096835285eff300cc44eee84be6"))


def _temp_auth(contents=b""):
    import tempfile
    handle, path = tempfile.mkstemp(prefix="xfilter-test-auth-")
    with open(handle, "wb") as out:
        out.write(contents)
    return path


def test_xauth_reads_what_the_real_tool_writes():
    path = _temp_auth(XAUTH_FROM_THE_REAL_TOOL)
    try:
        entries = core.read_xauth(path)
        assert len(entries) == 1, entries
        family, address, number, name, data = entries[0]
        assert family == core.XAUTH_LOCAL, family
        assert address == b"poderosa" and number == b"77", entries[0]
        assert name == core.COOKIE_NAME and len(data) == 16, entries[0]
        assert core.cookies_for(path, ":77") == [(core.COOKIE_NAME, data)]
    finally:
        import os; os.unlink(path)


def test_xauth_write_round_trips_and_appends():
    import os
    path = _temp_auth(XAUTH_FROM_THE_REAL_TOOL)
    try:
        made = core.cookies_for(path, ":88", create=True)
        assert len(made) == 1 and len(made[0][1]) == 16, made
        # the entry that was already there is still there: the file is
        # appended to, not rewritten, because it holds other displays' keys
        assert core.cookies_for(path, ":77")[0][1] == \
            XAUTH_FROM_THE_REAL_TOOL[-16:], "existing entry lost"
        assert core.cookies_for(path, ":88") == made, "not read back"
        assert [e[2] for e in core.read_xauth(path)] == [b"77", b"88"]
    finally:
        os.unlink(path)


def test_xauth_created_file_is_private():
    import os
    path = _temp_auth()
    os.unlink(path)                      # cookies_for must create it itself
    try:
        core.cookies_for(path, ":88", create=True)
        assert os.stat(path).st_mode & 0o777 == 0o600, "cookie file is readable"
    finally:
        os.unlink(path)


def test_xauth_returns_every_cookie_for_the_display():
    """One display often has several entries, and they need not agree.

    Returning them all is what lets working_cookie try each against the real
    server instead of trusting the first, which is how a stale entry left by
    an earlier session stops being fatal.
    """
    import os
    def entry(number, name, data):
        out = struct.pack(">H", core.XAUTH_LOCAL)
        for field in (b"host", number, name, data):
            out += struct.pack(">H", len(field)) + field
        return out
    path = _temp_auth(entry(b"20", core.COOKIE_NAME, b"A" * 16)
                      + entry(b"20", b"XDM-AUTHORIZATION-1", b"B" * 16)
                      + entry(b"21", core.COOKIE_NAME, b"C" * 16)
                      + entry(b"20", core.COOKIE_NAME, b"D" * 16))
    try:
        assert core.cookies_for(path, ":20") == [(core.COOKIE_NAME, b"A" * 16),
                                                 (core.COOKIE_NAME, b"D" * 16)]
        assert core.cookies_for(path, ":20.0") == core.cookies_for(path, ":20")
        assert core.cookies_for(path, ":21") == [(core.COOKIE_NAME, b"C" * 16)]
    finally:
        os.unlink(path)


def test_xauth_truncated_tail_keeps_what_parsed():
    """Half a file may still hold the cookie we need, so a short tail is not
    an exception -- and a caller that then finds nothing says so plainly."""
    import os
    path = _temp_auth(XAUTH_FROM_THE_REAL_TOOL + b"\x01\x00\x00\x08pod")
    try:
        assert len(core.read_xauth(path)) == 1, "truncated tail not dropped"
        assert core.cookies_for(path, ":77"), "good entry lost with the tail"
    finally:
        os.unlink(path)


def test_xauth_missing_entry_is_fatal_and_creates_nothing():
    import os
    path = _temp_auth()
    os.unlink(path)
    try:
        core.cookies_for(path, ":99")
    except SystemExit as exc:
        assert "no MIT-MAGIC-COOKIE-1" in str(exc), exc
    else:
        raise AssertionError("a missing cookie was not fatal")
    assert not os.path.exists(path), "created a file without create=True"


# --- trust domains -----------------------------------------------------------
#
# What these pin is the naming, which is the part that decides whether two
# domains can end up as one proxy. Whether a *running* proxy is found and
# reused is settled by a real handshake, so it is proved in e2e.sh, where
# there is a real proxy to find.


def test_domain_names_that_sanitise_alike_stay_apart():
    """Two domains must never land on one set of files.

    `me@host` and `me/host` reduce to the same safe name, and one set of
    files would mean one cookie, one display and therefore one trust domain
    holding two things that were meant to be separate.
    """
    assert xfilter.domain_key("me@host") != xfilter.domain_key("me/host")
    assert xfilter.domain_key("me@host") == xfilter.domain_key("me@host"), \
        "the same name gave two different keys"
    assert xfilter.domain_auth("me@host") != xfilter.domain_auth("me/host")


def test_domain_name_cannot_escape_its_directory():
    """The name comes from a command line and becomes a filename."""
    root = xfilter.domain_root()
    for hostile in ("../../etc/shadow", "..", "a/../../b", "x\0y", "/abs"):
        for path in (xfilter.domain_auth(hostile),
                     xfilter.domain_pid_file(hostile)):
            assert path.startswith(root + "/"), path
            assert "/" not in path[len(root) + 1:], path


def test_domain_display_search_is_stable_and_complete():
    """The display is derived, not remembered, so the order it is looked for
    in has to be the same every time -- and it has to cover the whole range,
    since a busy display must cost the next number rather than a failure."""
    order = xfilter.domain_displays("work@buildbox")
    assert order == xfilter.domain_displays("work@buildbox"), "not stable"
    assert sorted(order) == list(range(xfilter.DOMAIN_FIRST,
                                       xfilter.DOMAIN_LAST + 1)), order
    other = xfilter.domain_displays("other@buildbox")
    assert order[0] != other[0], "two domains start on the same display"


def test_a_domain_that_is_not_running_says_how_to_start_it():
    """The using side never starts anything, so its error has to be useful."""
    try:
        xfilter.domain_environment("no-such-domain-%d" % os.getpid())
    except SystemExit as exc:
        assert "--domain" in str(exc), exc
    else:
        raise AssertionError("a missing domain was not an error")


def main():
    """Run every test_* function, and report all failures rather than the first.

    Stopping at the first failure hides how far a change reaches: one edit to
    a shared table can break a dozen rules, and knowing that is the difference
    between "fix a typo" and "reconsider the table".  Sixty-odd tests with no
    fixtures and no I/O do not need a framework to do this -- they need a loop
    that keeps going and a tally at the end.
    """
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failures = []
    for test in tests:
        try:
            test()
        except AssertionError as exc:
            failures.append((test.__name__, str(exc) or "assertion failed"))
            print("FAIL", test.__name__)
        except Exception as exc:                       # a crash, not a verdict
            failures.append((test.__name__,
                             "%s: %s" % (type(exc).__name__, exc)))
            print("ERROR", test.__name__)
        else:
            print("PASS", test.__name__)
    if failures:
        print("\n%d of %d unit tests failed:\n" % (len(failures), len(tests)))
        for name, why in failures:
            print("    %-56s %s" % (name, why))
        raise SystemExit(1)
    print("\nall %d unit tests passed" % len(tests))


if __name__ == "__main__":
    main()
