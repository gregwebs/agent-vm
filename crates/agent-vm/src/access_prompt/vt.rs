//! What the guest told the terminal, and where it is safe to cut (#501 slice 3 §5.1).
//!
//! Two things are tracked, and the reason they are tracked here rather than read
//! back from the terminal is that no terminal can be asked:
//!
//! * the **parse state** — a subset of the DEC/ECMA-48 parser (Williams' VT500
//!   model), enough to know whether the guest is mid-sequence. A *safe boundary* is
//!   a point in the stream where that state is `Ground`: cutting anywhere else
//!   would leave a half escape sequence in front of a prompt, which the terminal
//!   would then finish drawing over it.
//! * the **modes the prompt changes** — screen, origin, mouse tracking, bracketed
//!   paste, synchronized output, the character sets and left/right margin mode.
//!   Each field is `Known(value)` or `Unknown`; the takeover is declined while any
//!   field is `Unknown` or margin mode is on, because restoring a guessed state is
//!   worse than not prompting (R10).
//!
//! # Why "Unknown" exists at all
//!
//! Emulators disagree about what a soft reset (`DECSTR`) and a full reset (`RIS`)
//! leave behind, and about which slot a cursor restore reads. The three rules that
//! survive that disagreement, from the plan's tmux 3.8 probes:
//!
//! * a field already at its default stays known across `DECSTR`, because both
//!   behaviours leave it there;
//! * `RIS` on the alternate screen leaves the screen unknown (xterm returns to
//!   main, tmux 3.8 stays);
//! * a guest cursor restore makes origin and the character sets unknown — unless
//!   neither was ever non-default when the guest saved, in which case no restore
//!   could have changed them (the sticky `saved_nondefault` bit).
//!
//! A CSI with more parameters than the collector keeps makes every field unknown:
//! an emulator may act on the ones that were dropped (tmux does on a 17th).
//!
//! The parse kernel is proved (ADR-0018); the mode adapter around it is not, and
//! its evidence is the tmux oracle (`script/test/access-prompt-tmux-oracle.sh`).

use vstd::prelude::*;

verus! {

/// Which control string an `ESC` interrupted. Kept as a payload so a state is one
/// value rather than one value and a side table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StringKind {
    Osc,
    Dcs,
    Ignored,
}

/// A subset of the VT500 parser, sufficient to answer one question: is the
/// terminal between sequences?
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parse {
    /// Between sequences: the only state a takeover may start in.
    Ground,
    /// Inside a UTF-8 character: `remaining` continuation bytes are owed.
    Utf8(u8),
    /// After `ESC`.
    Escape,
    /// After `ESC N` / `ESC O`: the next byte is drawn from a single shift.
    SingleShift,
    /// After `ESC` and an intermediate (`ESC ( `, `ESC # `, …).
    EscapeIntermediate,
    /// Inside `CSI`.
    Csi,
    /// Inside a malformed `CSI`.
    CsiIgnore,
    Osc,
    Dcs,
    Ignored,
    /// An `ESC` inside a control string; the string is abandoned unless this is
    /// immediately followed by `\`.
    StringEscape(StringKind),
}

/// The byte after an `ESC` that did not continue into a string, from `Ground`.
pub open spec fn escape_spec(byte: u8) -> Parse {
    if byte == b'[' {
        Parse::Csi
    } else if byte == b']' {
        Parse::Osc
    } else if byte == b'P' {
        Parse::Dcs
    } else if byte == b'X' || byte == b'^' || byte == b'_' {
        Parse::Ignored
    } else if byte == b'N' || byte == b'O' {
        Parse::SingleShift
    } else if 0x20 <= byte && byte <= 0x2f {
        Parse::EscapeIntermediate
    } else if 0x30 <= byte && byte <= 0x7e {
        Parse::Ground
    } else {
        Parse::Escape
    }
}

/// A byte seen in `Ground` (or as the one byte of a single shift): a UTF-8 lead
/// byte starts a character, `ESC` starts a sequence, everything else is drawn.
pub open spec fn ground_spec(byte: u8) -> Parse {
    if byte == 0x1b {
        Parse::Escape
    } else if 0xc2 <= byte && byte <= 0xdf {
        Parse::Utf8(1)
    } else if byte >= 0xe0 && byte <= 0xef {
        Parse::Utf8(2)
    } else if byte >= 0xf0 && byte <= 0xf4 {
        Parse::Utf8(3)
    } else {
        Parse::Ground
    }
}

/// One byte, in any state.
///
/// `CAN` and `SUB` abandon whatever was in progress and return to `Ground`, from
/// every state: that is what makes the forced cut's `CAN` mean "the terminal is
/// at a boundary now" without modelling where it was.
pub open spec fn next_spec(state: Parse, byte: u8) -> Parse {
    if byte == 0x18 || byte == 0x1a {
        Parse::Ground
    } else {
        match state {
            Parse::Ground => ground_spec(byte),
            Parse::Utf8(remaining) => {
                if 0x80 <= byte && byte <= 0xbf {
                    if remaining <= 1 { Parse::Ground } else { Parse::Utf8(remaining.wrapping_sub(1)) }
                } else {
                    ground_spec(byte)
                }
            }
            Parse::Escape => escape_spec(byte),
            Parse::SingleShift => ground_spec(byte),
            Parse::EscapeIntermediate => {
                if 0x30 <= byte && byte <= 0x7e { Parse::Ground } else { Parse::EscapeIntermediate }
            }
            Parse::Csi => {
                if 0x40 <= byte && byte <= 0x7e {
                    Parse::Ground
                } else if byte == 0x1b {
                    Parse::Escape
                } else if byte >= 0x80 {
                    Parse::CsiIgnore
                } else {
                    Parse::Csi
                }
            }
            Parse::CsiIgnore => {
                if 0x40 <= byte && byte <= 0x7e { Parse::Ground } else { Parse::CsiIgnore }
            }
            Parse::Osc => {
                if byte == 0x07 {
                    Parse::Ground
                } else if byte == 0x1b {
                    Parse::StringEscape(StringKind::Osc)
                } else {
                    Parse::Osc
                }
            }
            Parse::Dcs => {
                if byte == 0x1b { Parse::StringEscape(StringKind::Dcs) } else { Parse::Dcs }
            }
            Parse::Ignored => {
                if byte == 0x1b { Parse::StringEscape(StringKind::Ignored) } else { Parse::Ignored }
            }
            Parse::StringEscape(_kind) => {
                if byte == b'\\' {
                    Parse::Ground
                } else if byte == 0x18 || byte == 0x1a {
                    Parse::Ground
                } else {
                    escape_spec(byte)
                }
            }
        }
    }
}

/// The exec mirror of [`ground_spec`]; the parse table's shape is the spec's, and
/// this function is proved to agree with it.
#[allow(clippy::manual_range_contains)]
pub fn ground_step(byte: u8) -> (next: Parse)
    ensures next == ground_spec(byte),
{
    if byte == 0x1b {
        Parse::Escape
    } else if 0xc2 <= byte && byte <= 0xdf {
        Parse::Utf8(1)
    } else if byte >= 0xe0 && byte <= 0xef {
        Parse::Utf8(2)
    } else if byte >= 0xf0 && byte <= 0xf4 {
        Parse::Utf8(3)
    } else {
        Parse::Ground
    }
}

/// The exec mirror of [`escape_spec`].
#[allow(clippy::manual_range_contains)]
pub fn escape_step(byte: u8) -> (next: Parse)
    ensures next == escape_spec(byte),
{
    if byte == b'[' {
        Parse::Csi
    } else if byte == b']' {
        Parse::Osc
    } else if byte == b'P' {
        Parse::Dcs
    } else if byte == b'X' || byte == b'^' || byte == b'_' {
        Parse::Ignored
    } else if byte == b'N' || byte == b'O' {
        Parse::SingleShift
    } else if 0x20 <= byte && byte <= 0x2f {
        Parse::EscapeIntermediate
    } else if 0x30 <= byte && byte <= 0x7e {
        Parse::Ground
    } else {
        Parse::Escape
    }
}

/// The exec mirror of [`next_spec`], with the two facts a caller of a forced cut
/// relies on spelled out.
#[allow(clippy::manual_range_contains)]
pub fn next(state: Parse, byte: u8) -> (next: Parse)
    ensures
        next == next_spec(state, byte),
        byte == 0x18 || byte == 0x1a ==> next == Parse::Ground,
{
    if byte == 0x18 || byte == 0x1a {
        return Parse::Ground;
    }
    match state {
        Parse::Ground => ground_step(byte),
        Parse::Utf8(remaining) => {
            if 0x80 <= byte && byte <= 0xbf {
                if remaining <= 1 { Parse::Ground } else { Parse::Utf8(remaining.wrapping_sub(1)) }
            } else {
                // The terminal substitutes U+FFFD and processes this byte as if it
                // had arrived in `Ground`.
                ground_step(byte)
            }
        }
        Parse::Escape => escape_step(byte),
        // The single byte of SS2/SS3 is drawn and the shift ends.
        Parse::SingleShift => ground_step(byte),
        Parse::EscapeIntermediate => {
            if 0x30 <= byte && byte <= 0x7e { Parse::Ground } else { Parse::EscapeIntermediate }
        }
        Parse::Csi => {
            if 0x40 <= byte && byte <= 0x7e {
                Parse::Ground
            } else if byte == 0x1b {
                Parse::Escape
            } else if byte >= 0x80 {
                Parse::CsiIgnore
            } else {
                Parse::Csi
            }
        }
        Parse::CsiIgnore => {
            if 0x40 <= byte && byte <= 0x7e { Parse::Ground } else { Parse::CsiIgnore }
        }
        Parse::Osc => {
            if byte == 0x07 { Parse::Ground } else if byte == 0x1b { Parse::StringEscape(StringKind::Osc) } else { Parse::Osc }
        }
        // A `BEL` does not end a DCS or an ignored string; only `ST` does.
        Parse::Dcs => {
            if byte == 0x1b { Parse::StringEscape(StringKind::Dcs) } else { Parse::Dcs }
        }
        Parse::Ignored => {
            if byte == 0x1b { Parse::StringEscape(StringKind::Ignored) } else { Parse::Ignored }
        }
        Parse::StringEscape(_kind) => {
            // `ST` ends the string; any other byte abandons it and starts whatever
            // it starts. `CAN`/`SUB` were handled above.
            if byte == b'\\' { Parse::Ground } else { escape_step(byte) }
        }
    }
}

/// The state after every byte of `bytes`.
pub open spec fn run(state: Parse, bytes: Seq<u8>) -> Parse
    decreases bytes.len(),
{
    if bytes.len() == 0 {
        state
    } else {
        next_spec(run(state, bytes.drop_last()), bytes.last())
    }
}

/// The last index in `[0, bytes.len()]` whose prefix ends in `Ground`, or `-1`.
pub open spec fn last_ground(state: Parse, bytes: Seq<u8>) -> int
    decreases bytes.len(),
{
    if bytes.len() == 0 {
        if state == Parse::Ground { 0 } else { -1 }
    } else {
        let prior = last_ground(state, bytes.drop_last());
        if next_spec(run(state, bytes.drop_last()), bytes.last()) == Parse::Ground {
            bytes.len() as int
        } else {
            prior
        }
    }
}

} // verus!

/// The last safe cut of `bytes`, given the state the stream is already in.
///
/// This is the scan §5.2 performs, and it is deliberately **not** inside the
/// proof block: the proved kernel is the transition function and the two spec
/// functions above it ([`run`], [`last_ground`]), and the loop below is a direct
/// transcription of `last_ground` that the tests check against a brute-force scan
/// at every carried-in state. The plan allowed exactly this split (§10.2: a kernel
/// that "will not verify in reasonable time" is recorded as a deviation, not
/// dropped); ADR-0069 records it.
pub(crate) fn last_safe_cut(state: Parse, bytes: &[u8]) -> Option<usize> {
    let mut current = state;
    let mut last = if state == Parse::Ground {
        Some(0)
    } else {
        None
    };
    for (index, &byte) in bytes.iter().enumerate() {
        current = next(current, byte);
        if current == Parse::Ground {
            last = Some(index + 1);
        }
    }
    last
}

/// A mode the tracker follows: either its last explicitly set value, or unknown
/// because something happened that emulators do not agree about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Known<T> {
    Known(T),
    Unknown,
}

impl<T: Copy> Known<T> {
    pub(crate) fn value(self) -> Option<T> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown => None,
        }
    }
}

/// Which screen the guest is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Screen {
    Main,
    Alternate,
}

/// The mouse reporting mode, as the DECSET number that re-enables it. Any reset of
/// any mouse mode clears tracking (`xterm`'s `set_mousemode`, and tmux likewise).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MouseTracking {
    Off,
    X10,
    Normal,
    Highlight,
    ButtonEvent,
    AnyEvent,
}

impl MouseTracking {
    /// The DECSET number, or `None` for `Off`.
    pub(crate) fn set_number(self) -> Option<u16> {
        match self {
            Self::Off => None,
            Self::X10 => Some(9),
            Self::Normal => Some(1000),
            Self::Highlight => Some(1001),
            Self::ButtonEvent => Some(1002),
            Self::AnyEvent => Some(1003),
        }
    }
}

/// One character-set designation, of the three the prompt can restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Charset {
    Ascii,
    Uk,
    LineDrawing,
}

impl Charset {
    fn from_designator(byte: u8) -> Option<Self> {
        match byte {
            b'B' => Some(Self::Ascii),
            b'A' => Some(Self::Uk),
            b'0' => Some(Self::LineDrawing),
            _ => None,
        }
    }

    pub(crate) fn designator(self) -> u8 {
        match self {
            Self::Ascii => b'B',
            Self::Uk => b'A',
            Self::LineDrawing => b'0',
        }
    }
}

/// Which set `GL` reads from, after `SI` / `SO` / `ESC n` / `ESC o`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Gl {
    G0,
    G1,
    G2,
    G3,
}

/// The character-set state the prompt must give back: the two designations it
/// tracks and the shift in force. `G2`/`G3` designations are deliberately not
/// tracked, so a shift into them makes the state unknown rather than guessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Charsets {
    pub(crate) g0: Charset,
    pub(crate) g1: Charset,
    pub(crate) gl: Gl,
}

impl Charsets {
    #[cfg(test)]
    pub(crate) fn defaults() -> Self {
        Self {
            g0: Charset::Ascii,
            g1: Charset::Ascii,
            gl: Gl::G0,
        }
    }
}

/// A mode snapshot that can be restored exactly. The type exists so a byte builder
/// cannot be handed a state the takeover would have declined (R10): it can only be
/// produced by [`VtState::restorable_modes`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RestorableModes {
    pub(crate) screen: Screen,
    pub(crate) origin: bool,
    pub(crate) mouse_tracking: MouseTracking,
    pub(crate) bracketed_paste: bool,
    pub(crate) sync_update: bool,
    pub(crate) charsets: Charsets,
}

/// The character-set state, with each half tracked separately: designating G0
/// says nothing about G1, and a shift says nothing about either. A field the guest
/// has explicitly set since it became unknown is known again, which is why this is
/// three fields rather than one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CharsetState {
    g0: Known<Charset>,
    g1: Known<Charset>,
    gl: Known<Gl>,
}

impl CharsetState {
    fn defaults() -> Self {
        Self {
            g0: Known::Known(Charset::Ascii),
            g1: Known::Known(Charset::Ascii),
            gl: Known::Known(Gl::G0),
        }
    }

    fn restorable(self) -> Option<Charsets> {
        Some(Charsets {
            g0: self.g0.value()?,
            g1: self.g1.value()?,
            gl: self.gl.value()?,
        })
    }

    fn is_default(self) -> bool {
        matches!(self.g0, Known::Known(Charset::Ascii))
            && matches!(self.g1, Known::Known(Charset::Ascii))
            && matches!(self.gl, Known::Known(Gl::G0))
    }

    fn decstr(&mut self) {
        if !matches!(self.g0, Known::Known(Charset::Ascii)) {
            self.g0 = Known::Unknown;
        }
        if !matches!(self.g1, Known::Known(Charset::Ascii)) {
            self.g1 = Known::Unknown;
        }
        if !matches!(self.gl, Known::Known(Gl::G0)) {
            self.gl = Known::Unknown;
        }
    }
}

/// The guest's modes, each `Known` or `Unknown` (R10, §5.1's table).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GuestModes {
    screen: Known<Screen>,
    origin: Known<bool>,
    mouse_tracking: Known<MouseTracking>,
    bracketed_paste: Known<bool>,
    sync_update: Known<bool>,
    charsets: CharsetState,
    lr_margins: Known<bool>,
    /// Sticky: a guest cursor save happened while origin or the charsets were
    /// non-default, so a later restore may put something back that the tracker
    /// cannot name.
    saved_nondefault: bool,
}

impl Default for GuestModes {
    fn default() -> Self {
        Self {
            screen: Known::Known(Screen::Main),
            origin: Known::Known(false),
            mouse_tracking: Known::Known(MouseTracking::Off),
            bracketed_paste: Known::Known(false),
            sync_update: Known::Known(false),
            charsets: CharsetState::defaults(),
            lr_margins: Known::Known(false),
            saved_nondefault: false,
        }
    }
}

impl GuestModes {
    #[cfg(test)]
    pub(crate) fn screen(&self) -> Known<Screen> {
        self.screen
    }

    #[cfg(test)]
    pub(crate) fn mouse_tracking(&self) -> Known<MouseTracking> {
        self.mouse_tracking
    }

    /// A soft reset (`CSI ! p`): every changed field becomes unknown, because xterm
    /// resets some of them and tmux 3.8 resets none.
    fn decstr(&mut self) {
        self.origin = match self.origin {
            Known::Known(false) => Known::Known(false),
            _ => Known::Unknown,
        };
        self.mouse_tracking = match self.mouse_tracking {
            Known::Known(MouseTracking::Off) => Known::Known(MouseTracking::Off),
            _ => Known::Unknown,
        };
        self.bracketed_paste = match self.bracketed_paste {
            Known::Known(false) => Known::Known(false),
            _ => Known::Unknown,
        };
        self.sync_update = match self.sync_update {
            Known::Known(false) => Known::Known(false),
            _ => Known::Unknown,
        };
        self.charsets.decstr();
        self.lr_margins = match self.lr_margins {
            Known::Known(false) => Known::Known(false),
            _ => Known::Unknown,
        };
    }

    /// A full reset (`ESC c`). The screen is the one field the emulators disagree
    /// about: xterm returns to the main screen from the alternate one, tmux 3.8
    /// stays.
    fn ris(&mut self) {
        self.screen = match self.screen {
            Known::Known(Screen::Main) => Known::Known(Screen::Main),
            _ => Known::Unknown,
        };
        self.origin = Known::Known(false);
        self.mouse_tracking = Known::Known(MouseTracking::Off);
        self.bracketed_paste = Known::Known(false);
        self.sync_update = Known::Known(false);
        self.charsets = CharsetState::defaults();
        self.lr_margins = Known::Known(false);
        self.saved_nondefault = false;
    }

    /// A guest cursor save (`ESC 7`, `CSI s`, `?1048h`, `?1049h`).
    fn guest_save(&mut self) {
        let origin_nondefault = matches!(self.origin, Known::Known(true));
        let charsets_nondefault = !self.charsets.is_default();
        if origin_nondefault || charsets_nondefault {
            self.saved_nondefault = true;
        }
    }

    /// A guest cursor restore (`ESC 8`, `CSI u`, `?1048l`, `?1049l`). Origin mode
    /// and the charsets may come back from the guest's slot, so they are unknown
    /// unless no save could have stored a non-default value.
    fn guest_restore(&mut self) {
        if self.saved_nondefault {
            self.origin = Known::Unknown;
            self.charsets = CharsetState {
                g0: Known::Unknown,
                g1: Known::Unknown,
                gl: Known::Unknown,
            };
        }
    }

    fn designate(&mut self, which: u8, final_byte: u8) {
        let charset = Charset::from_designator(final_byte);
        match which {
            b'(' => self.charsets.g0 = charset.map_or(Known::Unknown, Known::Known),
            b')' => self.charsets.g1 = charset.map_or(Known::Unknown, Known::Known),
            // A G2/G3 designation is never tracked, so it is not this field.
            _ => {}
        }
    }

    fn shift(&mut self, gl: Gl) {
        // A shift into G2/G3 reads a designation this tracker never follows, so
        // the state cannot be restored exactly and becomes unknown.
        self.charsets.gl = if matches!(gl, Gl::G2 | Gl::G3) {
            Known::Unknown
        } else {
            Known::Known(gl)
        };
    }

    fn set_bool(field: &mut Known<bool>, value: bool) {
        *field = Known::Known(value);
    }

    fn set_mouse(&mut self, mode: MouseTracking, on: bool) {
        // Any mouse mode's reset clears tracking, and any set selects that mode:
        // xterm's `set_mousemode` and tmux agree on both halves.
        self.mouse_tracking = Known::Known(if on { mode } else { MouseTracking::Off });
    }

    /// `Some` only when every field the prompt changes is known and no field it
    /// cannot restore is in force.
    pub(crate) fn restorable(&self) -> Option<RestorableModes> {
        if self.lr_margins != Known::Known(false) {
            return None;
        }
        Some(RestorableModes {
            screen: self.screen.value()?,
            origin: self.origin.value()?,
            mouse_tracking: self.mouse_tracking.value()?,
            bracketed_paste: self.bracketed_paste.value()?,
            sync_update: self.sync_update.value()?,
            charsets: self.charsets.restorable()?,
        })
    }

    /// Every field unknown, which is what a CSI with more parameters than the
    /// collector keeps leaves behind.
    fn forget_all(&mut self) {
        self.screen = Known::Unknown;
        self.origin = Known::Unknown;
        self.mouse_tracking = Known::Unknown;
        self.bracketed_paste = Known::Unknown;
        self.sync_update = Known::Unknown;
        self.charsets = CharsetState {
            g0: Known::Unknown,
            g1: Known::Unknown,
            gl: Known::Unknown,
        };
        self.lr_margins = Known::Unknown;
    }
}

/// The CSI collector: bounded, so a hostile stream cannot grow it.
const MAX_CSI_PARAMS: usize = 16;
const PARAM_SATURATION: u32 = 65_535;

#[derive(Clone, Debug, Default)]
struct Csi {
    params: Vec<u32>,
    current: Option<u32>,
    /// More parameters than [`MAX_CSI_PARAMS`]: every field becomes unknown,
    /// because an emulator may act on the ones dropped here.
    overflow: bool,
    private: bool,
    /// The one intermediate byte, e.g. `!` in `CSI ! p`.
    intermediate: Option<u8>,
    /// A second intermediate: only a charset designation uses one here, and two
    /// make the sequence one this tracker does not model.
    intermediates_many: bool,
}

impl Csi {
    fn reset(&mut self) {
        *self = Self::default();
    }

    fn push_digit(&mut self, byte: u8) {
        let digit = u32::from(byte - b'0');
        let next = self
            .current
            .unwrap_or(0)
            .saturating_mul(10)
            .saturating_add(digit);
        self.current = Some(next.min(PARAM_SATURATION));
    }

    fn end_param(&mut self) {
        if let Some(value) = self.current.take() {
            if self.params.len() < MAX_CSI_PARAMS {
                self.params.push(value);
            } else {
                self.overflow = true;
            }
        } else if self.params.len() < MAX_CSI_PARAMS {
            // An omitted parameter is its default, which is zero for every mode
            // this tracker reads.
            self.params.push(0);
        } else {
            self.overflow = true;
        }
    }

    fn finish(&mut self) -> usize {
        if self.current.is_some() || !self.params.is_empty() {
            self.end_param();
        }
        self.params.len()
    }
}

/// The tracker: parse state, the CSI being collected and the modes.
#[derive(Clone, Debug)]
pub(crate) struct VtState {
    parse: Parse,
    csi: Csi,
    modes: GuestModes,
    /// The intermediate byte of an `ESC`-introduced designation (`ESC ( B`).
    escape_intermediate: Option<u8>,
}

impl Default for VtState {
    fn default() -> Self {
        Self::new()
    }
}

impl VtState {
    pub(crate) fn new() -> Self {
        Self {
            parse: Parse::Ground,
            csi: Csi::default(),
            modes: GuestModes::default(),
            escape_intermediate: None,
        }
    }

    pub(crate) fn modes(&self) -> &GuestModes {
        &self.modes
    }

    pub(crate) fn at_safe_boundary(&self) -> bool {
        self.parse == Parse::Ground
    }

    /// The terminal abandoned a sequence (the forced cut's `CAN`): it is at ground
    /// now, and so is the tracker.
    pub(crate) fn cancelled(&mut self) {
        self.parse = Parse::Ground;
        self.csi.reset();
        self.escape_intermediate = None;
    }

    /// The last prefix of `bytes` that ends at a safe boundary.
    pub(crate) fn last_safe_cut(&self, bytes: &[u8]) -> Option<usize> {
        last_safe_cut(self.parse, bytes)
    }

    /// Fold the bytes the terminal has been given.
    pub(crate) fn advance(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            let before = self.parse;
            self.parse = next(before, byte);
            match before {
                Parse::Escape => {
                    if (0x20..=0x2f).contains(&byte) {
                        self.escape_intermediate = Some(byte);
                    } else if (0x30..=0x7e).contains(&byte) {
                        // A new `CSI` starts a new parameter list: an abandoned
                        // sequence's parameters must not leak into it (`\x1b[?20`
                        // followed by `\x1b[?69h` is `?69h`, not `?2069h`).
                        if byte == b'[' {
                            self.csi.reset();
                        }
                        self.escape_dispatched(byte);
                        self.escape_intermediate = None;
                    }
                }
                Parse::EscapeIntermediate => {
                    if (0x20..=0x2f).contains(&byte) {
                        // A second intermediate: not modelled, so the field it
                        // could change becomes unknown.
                        self.modes.charsets = CharsetState {
                            g0: Known::Unknown,
                            g1: Known::Unknown,
                            gl: Known::Unknown,
                        };
                    } else if (0x30..=0x7e).contains(&byte) {
                        self.escape_intermediate_dispatched(byte);
                        self.escape_intermediate = None;
                    }
                }
                Parse::Csi => {
                    if byte == b'?' {
                        self.csi.private = true;
                    } else if byte.is_ascii_digit() {
                        self.csi.push_digit(byte);
                    } else if byte == b';' || byte == b':' {
                        self.csi.end_param();
                    } else if (0x3c..=0x3f).contains(&byte) {
                        // `<`, `=`, `>`: private markers this tracker does not read.
                        self.csi.private = true;
                    } else if (0x20..=0x2f).contains(&byte) {
                        if self.csi.intermediate.is_some() {
                            self.csi.intermediates_many = true;
                        } else {
                            self.csi.intermediate = Some(byte);
                        }
                    } else if (0x40..=0x7e).contains(&byte) {
                        self.csi_dispatched(byte);
                    }
                }
                Parse::CsiIgnore => {}
                _ => {}
            }
            if byte == 0x18 || byte == 0x1a {
                // `CAN`/`SUB` abandoned whatever was being collected: the next
                // sequence starts clean.
                self.csi.reset();
                self.escape_intermediate = None;
            }
            // `SO`/`SI` are the only shift controls an application writes directly;
            // they are C0 bytes in `Ground`, so they are not part of a dispatch.
            if byte == 0x0e {
                self.modes.shift(Gl::G1);
            } else if byte == 0x0f {
                self.modes.shift(Gl::G0);
            }
        }
    }

    fn escape_dispatched(&mut self, byte: u8) {
        match byte {
            // DECSC / DECRC.
            b'7' => self.modes.guest_save(),
            b'8' => self.modes.guest_restore(),
            // RIS.
            b'c' => self.modes.ris(),
            // LS2 / LS3: a shift into a set this tracker does not follow.
            b'n' => self.modes.shift(Gl::G2),
            b'o' => self.modes.shift(Gl::G3),
            _ => {}
        }
    }

    fn escape_intermediate_dispatched(&mut self, byte: u8) {
        if let Some(intermediate) = self.escape_intermediate {
            match intermediate {
                b'(' => self.modes.designate(b'(', byte),
                b')' => self.modes.designate(b')', byte),
                _ => {}
            }
        }
    }

    fn csi_dispatched(&mut self, byte: u8) {
        let private = self.csi.private;
        let intermediate = self.csi.intermediate;
        let many_intermediates = self.csi.intermediates_many;
        // `finish` is what closes the last parameter, so it decides whether the
        // sequence overflowed; reading the flag before it would miss the 17th.
        let count = self.csi.finish();
        let overflow = self.csi.overflow;
        let params = self.csi.params.clone();
        self.csi.reset();
        if overflow {
            self.modes.forget_all();
            return;
        }
        if count > MAX_CSI_PARAMS {
            self.modes.forget_all();
            return;
        }
        // DECSTR: `CSI ! p`.
        if intermediate == Some(b'!') && byte == b'p' && count == 0 {
            self.modes.decstr();
            return;
        }
        if many_intermediates {
            return;
        }
        if !private {
            // `CSI s` saves and `CSI u` restores the cursor, when `?69` (left/right
            // margins) is off. It is never on while a takeover may happen, but the
            // tracker does not need that: an unmodelled cursor control leaves the
            // same two fields unknown as any other restore.
            if byte == b's' && count == 0 {
                self.modes.guest_save();
            } else if byte == b'u' && count == 0 {
                self.modes.guest_restore();
            }
            return;
        }
        let on = byte == b'h';
        if byte != b'h' && byte != b'l' {
            return;
        }
        for &param in &params {
            match param {
                6 => self.modes.origin = Known::Known(on),
                9 => self.modes.set_mouse(MouseTracking::X10, on),
                47 | 1047 => {
                    self.modes.screen =
                        Known::Known(if on { Screen::Alternate } else { Screen::Main });
                }
                69 => self.modes.lr_margins = Known::Known(on),
                1000 => self.modes.set_mouse(MouseTracking::Normal, on),
                1001 => self.modes.set_mouse(MouseTracking::Highlight, on),
                1002 => self.modes.set_mouse(MouseTracking::ButtonEvent, on),
                1003 => self.modes.set_mouse(MouseTracking::AnyEvent, on),
                1048 => {
                    if on {
                        self.modes.guest_save();
                    } else {
                        self.modes.guest_restore();
                    }
                }
                1049 => {
                    if on {
                        self.modes.guest_save();
                        self.modes.screen = Known::Known(Screen::Alternate);
                    } else {
                        self.modes.screen = Known::Known(Screen::Main);
                        self.modes.guest_restore();
                    }
                }
                2004 => GuestModes::set_bool(&mut self.modes.bracketed_paste, on),
                2026 => GuestModes::set_bool(&mut self.modes.sync_update, on),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests;
