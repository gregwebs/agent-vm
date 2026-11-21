//! Every byte the prompt writes (§5.3–§5.7), as pure builders over
//! [`RestorableModes`], a [`Size`] and the question's own text.
//!
//! The rules that make drawing insensitive to the modes the prompt does **not**
//! change:
//!
//! * every row is positioned absolutely (`CSI r ; 1 H`) and erased before it is
//!   written (`CSI 2 K`), so autowrap and insert mode cannot move anything;
//! * no line feed is ever written, so scroll margins cannot scroll the prompt;
//! * every line contains no control byte. **Guest-derived** text is printable ASCII
//!   (it went through [`crate::config::escape_str`], whose width is its length). The
//!   destination **cell** is the one exception: it is `agent-vm access`'s own
//!   rendering, passed through verbatim so the prompt names the destination exactly
//!   as the command does (R24), and that rendering uses the middle dot `·` as a
//!   separator. Prompt rows may therefore contain that one non-ASCII character.
//! * every line is at most `cols − 1` characters wide, so the last column's pending
//!   wrap is never armed.
//!
//! There is no clipping path: [`layout`] returns `None` when the question does not
//! fit, and the relay declines the takeover (R25). A takeover that would hide a
//! safety-relevant line is not one this module can produce.

use super::Size;
use super::vt::{Charsets, Gl, RestorableModes, Screen};

/// The narrowest terminal the prompt draws in (R25).
pub(crate) const MIN_COLS: u16 = 40;
/// The shortest terminal the prompt draws in (R25). The question grew an input row,
/// a status row and the two-word key column, so the tallest question (the
/// project-only offer, whose `p` row wraps) needs twenty rows at [`MIN_COLS`]; the
/// tests hold this to the layout itself.
pub(crate) const MIN_ROWS: u16 = 19;

/// Whether bracketed paste is on during the prompt. #494 settled **off**; operator
/// decision D4 proposes on, and would flip this constant and nothing else.
pub(crate) const BRACKETED_PASTE_DURING_PROMPT: bool = false;

const ESC: u8 = 0x1b;
const CAN: u8 = 0x18;

fn csi(bytes: &mut Vec<u8>, params: &str, final_byte: u8) {
    bytes.push(ESC);
    bytes.push(b'[');
    bytes.extend_from_slice(params.as_bytes());
    bytes.push(final_byte);
}

fn erase_row(bytes: &mut Vec<u8>, row: usize) {
    csi(bytes, &(row + 1).to_string(), b'H');
    csi(bytes, "2", b'K');
}

struct Builder(Vec<u8>);

impl Builder {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self
    }

    fn csi(&mut self, params: &str, final_byte: u8) -> &mut Self {
        csi(&mut self.0, params, final_byte);
        self
    }

    fn print(&mut self, text: &str) -> &mut Self {
        self.0.extend_from_slice(text.as_bytes());
        self
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// What the question offers, as the derivation decided (R7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OfferText {
    /// `s` and `p`.
    SessionOrProject,
    /// Only a record for the next launch, because this launch did not intercept
    /// the hostname's port (#491). The port is named when the refusal stated one.
    ProjectNextLaunch { port: Option<u16> },
}

/// The destination cell, as `agent-vm access` printed it.
///
/// The cell is built by [`crate::refusal::RefusalEntry::destination_cell`], which has
/// already escaped every byte to printable ASCII. Escaping it again turned the
/// table's ` · ` separator into `\\xc2\\xb7` and doubled every backslash, so the
/// prompt no longer named the destination exactly as the command does (R24). The
/// newtype is what makes "already escaped" a fact the screen can rely on: a guest
/// string can only enter as [`Cell::from_guest`], which escapes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Cell(String);

impl Cell {
    /// A cell the refusal table already rendered.
    pub(crate) fn from_table(cell: String) -> Self {
        Self(cell)
    }

    /// Guest- or test-supplied text: escaped to printable ASCII here, once.
    pub(crate) fn from_guest(text: &str) -> Self {
        Self(crate::config::escape_str(text))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// One question, as the screen needs it. The destination is a [`Cell`]: everything
/// else here is plain text the screen escapes itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct View {
    /// The destination cell, as `agent-vm access` prints it.
    pub(crate) destination: Cell,
    /// The line typed so far, already lower-cased letters by [`super::guard`].
    pub(crate) typed: String,
    pub(crate) count: u64,
    pub(crate) session: String,
    pub(crate) offer: OfferText,
    /// Destinations waiting for their own takeover.
    pub(crate) waiting: u64,
    /// Refusals past the waiting cap, left to `agent-vm access`.
    pub(crate) overflow: u64,
}

/// The status the question is showing. There is no "can I answer yet" state: the
/// line is always open, and Enter is what submits it (§4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    /// Nothing beyond the question itself.
    Asking,
    /// A grant is running.
    Allowing,
}

impl Status {
    fn text(self) -> Option<&'static str> {
        match self {
            Self::Asking => None,
            Self::Allowing => Some("allowing..."),
        }
    }
}

/// The question's own sentence, above the instruction.
pub(crate) const QUESTION: &str = "How should this request be treated?";
/// What the input row is for. The operator's line is echoed below it.
pub(crate) const INSTRUCTION: &str = "Type one of the below letters and press enter:";
/// The last line of the question: why the request already failed.
pub(crate) const ALREADY_FAILED: &str = "The request has already failed; retry it after allowing.";
/// The timeout note, dropped by the compact form.
pub(crate) const TIMEOUT_NOTE: &str = "refuses in 60 s if unanswered";
/// One key row: the letter, the word it may be spelled as, and what it does. The
/// letter and word are the answer itself — a test holds them to
/// [`super::guard::answer_of`], so the question cannot offer a spelling the answer
/// does not take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Key {
    pub(crate) letter: char,
    pub(crate) word: &'static str,
    pub(crate) text: &'static str,
}

/// The column the descriptions line up in: the widest word, so one row's text never
/// starts left of another's.
pub(crate) const WORD_COLUMN: usize = 7;

/// The four keys, in the order the question draws them.
pub(crate) const SESSION_KEY: Key = Key {
    letter: 's',
    word: "session",
    text: "allow for this session",
};
pub(crate) const PROJECT_KEY: Key = Key {
    letter: 'p',
    word: "project",
    text: "allow for this project, now and at every launch",
};
pub(crate) const DENY_KEY: Key = Key {
    letter: 'd',
    word: "deny",
    text: "keep refusing (also Enter or Esc)",
};
pub(crate) const NEVER_KEY: Key = Key {
    letter: 'n',
    word: "never",
    text: "keep refusing, and stop asking about it in this session",
};

/// Every key either offer can draw, for tests that hold them to the answer table.
#[cfg(test)]
pub(crate) const ALL_KEYS: [Key; 4] = [SESSION_KEY, PROJECT_KEY, DENY_KEY, NEVER_KEY];

/// The grant's outcome, as the result frame shows it (§5.5, R20).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResultView {
    /// The sentence `agent-vm access allow` prints (`GrantResult::report`'s text)
    /// — or, for an answer from elsewhere, the prompt's own line.
    pub(crate) sentence: String,
    /// The command that undoes what was allowed or recorded.
    pub(crate) undo: Option<String>,
    /// Whether to add "Retry the request now." — every outcome except an answer
    /// given elsewhere carries it.
    pub(crate) retry: bool,
}

/// A laid-out question: every row to draw, and the input row the cursor sits on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Layout {
    rows: Vec<String>,
    /// The row (0-based) holding the typed line and its `_`.
    input_row: usize,
    /// The column (1-based) the cursor is placed at: just after the typed text.
    cursor_col: usize,
    size: Size,
}

impl Layout {
    /// The absolute row (0-based) the visibility position is on.
    pub(crate) fn input_row(&self) -> usize {
        self.input_row
    }

    /// The 1-based column the cursor is placed on when the question is drawn.
    pub(crate) fn cursor_col(&self) -> usize {
        self.cursor_col
    }
}

/// Word-wrap `text` into `width`-wide rows. `first` prefixes the first row and
/// `continuation` every later one; both count against the width. Words longer than
/// the available width are broken, because a line may never exceed it.
fn wrap(text: &str, width: usize, first: &str, continuation: &str, rows: &mut Vec<String>) {
    let mut line = first.to_owned();
    let mut started = false;
    for word in text.split_whitespace() {
        if started && line.len() + 1 + word.len() <= width {
            line.push(' ');
            line.push_str(word);
            continue;
        }
        if started {
            rows.push(std::mem::take(&mut line));
            if continuation.len() < width {
                line.push_str(continuation);
            }
        }
        let mut rest = word;
        while !rest.is_empty() {
            let available = width.saturating_sub(line.len());
            if available == 0 {
                // No room left on this row. Start a fresh one — but only with an
                // indent that still leaves room for a character. On a terminal this
                // narrow (a resize under a result, say) the loop must still consume a
                // byte every turn; appending an indent wider than the row did not, and
                // the synchronous handler never returned (round 3, C-R2-1).
                rows.push(std::mem::take(&mut line));
                if continuation.len() < width {
                    line.push_str(continuation);
                    continue;
                }
            }
            let take = width.saturating_sub(line.len()).max(1).min(rest.len());
            let (head, tail) = rest.split_at(take);
            line.push_str(head);
            rest = tail;
            if !rest.is_empty() {
                rows.push(std::mem::take(&mut line));
                if continuation.len() < width {
                    line.push_str(continuation);
                }
            }
        }
        started = true;
    }
    if started || line.len() > first.len() {
        rows.push(line);
    }
}

/// Break `text` at any character, with a hanging indent: the destination cell is
/// ASCII and may have no spaces at all (R25).
fn wrap_break(text: &str, width: usize, first: &str, continuation: &str, rows: &mut Vec<String>) {
    let mut line = first.to_owned();
    for character in text.chars() {
        if line.chars().count() >= width {
            rows.push(std::mem::take(&mut line));
            line.push_str(continuation);
        }
        line.push(character);
    }
    rows.push(line);
}

fn count_text(view: &View) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if view.waiting > 0 {
        parts.push(format!("+{} more waiting", view.waiting));
    }
    if view.overflow > 0 {
        parts.push(format!("+{} more: agent-vm access", view.overflow));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

/// Wrap one key line: the letter, its word, then what it does, with continuation
/// rows lined up under the text rather than under the letter.
fn wrap_key(key: Key, text: &str, width: usize, rows: &mut Vec<String>) {
    let first = format!(
        "  {} {:<width$}  ",
        key.letter,
        key.word,
        width = WORD_COLUMN
    );
    let continuation = " ".repeat(first.len());
    wrap(text, width, &first, &continuation, rows);
}

/// The row under the input line: the question's own state and what waits behind it.
/// Always present, so the rows below keep their place whatever the status is.
fn push_status(rows: &mut Vec<String>, view: &View, status: Status, width: usize) {
    let mut parts: Vec<&str> = Vec::new();
    if let Some(text) = status.text() {
        parts.push(text);
    }
    let count = count_text(view);
    if let Some(count) = &count {
        parts.push(count);
    }
    if parts.is_empty() {
        rows.push(String::new());
    } else {
        wrap(&parts.join(" "), width, "  ", "  ", rows);
    }
}

/// One layout attempt. `compact` drops the blank separators, the status row and the
/// timeout note, which is what lets the minimum question fit a narrow terminal
/// (AC16); at any larger size the spaced form is used and the question is never
/// clipped either way.
fn attempt(view: &View, size: Size, compact: bool, status: Status) -> Option<Layout> {
    if size.cols < MIN_COLS || size.rows < MIN_ROWS {
        return None;
    }
    let width = usize::from(size.cols - 1);
    let mut rows: Vec<String> = Vec::new();
    // The header is wrapped, never clipped: at 40 columns it used to read
    // "…refused a network" (finding 11), which is a safety-relevant line.
    wrap(
        "agent-vm: the sandbox refused a network request from the guest",
        width,
        "",
        "",
        &mut rows,
    );
    if !compact {
        rows.push(String::new());
    }
    wrap_break(view.destination.as_str(), width, "  ", "    ", &mut rows);
    wrap(
        // The count and the session ID, both named as R24 requires.
        &format!(
            "Refused {} time(s), session {}.",
            view.count,
            crate::config::escape_str(&view.session)
        ),
        width,
        "  ",
        "  ",
        &mut rows,
    );
    if !compact {
        rows.push(String::new());
    }
    wrap(QUESTION, width, "", "", &mut rows);
    wrap(INSTRUCTION, width, "", "", &mut rows);
    // The input row: what has been typed, then the cursor's `_`. It is the row the
    // visibility position is on, so it is always drawn even when it is empty.
    let typed = crate::config::escape_str(&view.typed);
    let cursor_col = typed.len() + 1;
    rows.push(format!("{typed}_"));
    let input_row = rows.len() - 1;
    // The status row is also the blank line the question needs under the input row:
    // one row, whichever it is showing, so nothing below it moves (R17) and the
    // question costs no line it does not use. The compact form has no separators at
    // all, so it keeps the row only when it has something to say.
    if !compact || status.text().is_some() || count_text(view).is_some() {
        push_status(&mut rows, view, status, width);
    }
    match view.offer {
        OfferText::SessionOrProject => {
            wrap_key(SESSION_KEY, SESSION_KEY.text, width, &mut rows);
            wrap_key(PROJECT_KEY, PROJECT_KEY.text, width, &mut rows);
        }
        OfferText::ProjectNextLaunch { port } => {
            let text = match port {
                Some(port) => format!(
                    "allow for this project from the next launch (this launch does not intercept port {port})"
                ),
                None => "allow for this project from the next launch".to_owned(),
            };
            wrap_key(PROJECT_KEY, &text, width, &mut rows);
        }
    }
    wrap_key(DENY_KEY, DENY_KEY.text, width, &mut rows);
    wrap_key(NEVER_KEY, NEVER_KEY.text, width, &mut rows);
    if !compact {
        rows.push(String::new());
    }
    wrap(ALREADY_FAILED, width, "", "", &mut rows);
    if !compact {
        rows.push(TIMEOUT_NOTE.to_owned());
    }
    if rows.len() > usize::from(size.rows) {
        return None;
    }
    Some(Layout {
        rows,
        input_row,
        cursor_col,
        size,
    })
}

/// Lay the question out with the status it is currently showing, or decline it
/// (R25).
pub(crate) fn layout_with(view: &View, size: Size, status: Status) -> Option<Layout> {
    attempt(view, size, false, status).or_else(|| attempt(view, size, true, status))
}

/// The question's first layout. Only tests ask directly now; the relay always names
/// the status (`layout_with`).
#[cfg(test)]
pub(crate) fn layout(view: &View, size: Size) -> Option<Layout> {
    layout_with(view, size, Status::Asking)
}

/// The surface the prompt draws on: which screen it saves, and what the status
/// row is.
fn enter_screen(builder: &mut Builder, modes: &RestorableModes) {
    match modes.screen {
        Screen::Main => {
            // Saves the cursor and SGR, and clears the alternate screen.
            builder.csi("?1049", b'h');
        }
        Screen::Alternate => {
            // `DECSC`: `?1049h` would clear the guest's screen and `?1049l` would
            // drop it to the main one.
            builder.raw(&[ESC, b'7']);
        }
    }
}

/// The modes the prompt turns off, one `CSI ? Pm l` each: a few terminals mishandle
/// multi-parameter DECSET.
fn enter_modes(builder: &mut Builder, modes: &RestorableModes) {
    if modes.sync_update {
        builder.csi("?2026", b'l');
    }
    for number in ["?1003", "?1002", "?1001", "?1000", "?9"] {
        builder.csi(number, b'l');
    }
    builder.csi(
        "?2004",
        if BRACKETED_PASTE_DURING_PROMPT {
            b'h'
        } else {
            b'l'
        },
    );
    builder.csi("?6", b'l');
    // Kitty keyboard: push flags 0. A terminal without the protocol ignores it.
    builder.csi(">0", b'u');
    builder.csi("0", b'm');
    builder.raw(&[ESC, b'(', b'B']);
    builder.raw(&[0x0f]);
}

/// The enter frame of §5.3, and the row the visibility position is on (1-based).
pub(crate) fn enter(
    modes: &RestorableModes,
    layout: &Layout,
    forced_cut: bool,
    ask_position: bool,
) -> (Vec<u8>, u16) {
    let mut builder = Builder::new();
    if forced_cut {
        builder.raw(&[CAN]);
    }
    enter_screen(&mut builder, modes);
    enter_modes(&mut builder, modes);
    // Home, then erase the surface the prompt draws on.
    builder.csi("", b'H').csi("2", b'J');
    for (row, text) in layout.rows.iter().enumerate() {
        erase_row(&mut builder.0, row);
        builder.print(text);
    }
    let input_row = layout.input_row + 1;
    builder.csi(&format!("{input_row};{}", layout.cursor_col), b'H');
    if ask_position {
        builder.csi("6", b'n');
    }
    (builder.finish(), input_row as u16)
}

/// Redraw the whole question, in place: used after a resize, when the rows moved.
pub(crate) fn redraw(layout: &Layout) -> Vec<u8> {
    let mut builder = Builder::new();
    for (row, text) in layout.rows.iter().enumerate() {
        erase_row(&mut builder.0, row);
        builder.print(text);
    }
    for row in layout.rows.len()..usize::from(layout.size.rows) {
        erase_row(&mut builder.0, row);
    }
    builder.csi(
        &format!("{};{}", layout.input_row + 1, layout.cursor_col),
        b'H',
    );
    builder.finish()
}

/// The character-set bytes a leave re-emits (tmux's `?1049l` restores neither the
/// designation nor the shift).
fn charsets(builder: &mut Builder, charsets: Charsets) {
    if charsets.g0 != super::vt::Charset::Ascii {
        builder.raw(&[ESC, b'(', charsets.g0.designator()]);
    }
    if charsets.g1 != super::vt::Charset::Ascii {
        builder.raw(&[ESC, b')', charsets.g1.designator()]);
    }
    if charsets.gl == Gl::G1 {
        builder.raw(&[0x0e]);
    }
}

/// The guest's modes as they were, in §5.6's order.
fn leave_modes(builder: &mut Builder, modes: &RestorableModes) {
    if let Some(number) = modes.mouse_tracking.set_number() {
        builder.csi(&format!("?{number}"), b'h');
    }
    if modes.bracketed_paste {
        builder.csi("?2004", b'h');
    }
    // Last, so the held output that follows carries the guest's own end of update.
    if modes.sync_update {
        builder.csi("?2026", b'h');
    }
}

/// The leave frame of §5.6, and the row the cursor is left on (1-based).
pub(crate) fn leave(modes: &RestorableModes) -> (Vec<u8>, u16) {
    let mut builder = Builder::new();
    builder.csi("0", b'm');
    builder.csi("", b'H');
    builder.csi("2", b'J');
    builder.csi("<", b'u');
    if modes.origin {
        // Setting origin mode homes the cursor, so it comes before the restore.
        builder.csi("?6", b'h');
    }
    match modes.screen {
        Screen::Main => {
            builder.csi("?1049", b'l');
        }
        Screen::Alternate => {
            builder.raw(&[ESC, b'8']);
        }
    }
    charsets(&mut builder, modes.charsets);
    leave_modes(&mut builder, modes);
    (builder.finish(), 1)
}

/// The host restore of §5.7: written only by the writer, only at an abnormal end.
///
/// It contains no erase, so a second copy keeps the main screen, and it is correct
/// from every prefix of an enter or a leave — which is why no progress state is
/// needed anywhere (§6.1).
pub(crate) fn host_restore() -> Vec<u8> {
    let mut builder = Builder::new();
    builder.raw(&[CAN]);
    builder.csi("0", b'm');
    builder.csi("<", b'u');
    builder.csi("?6", b'l');
    builder.csi("", b'r');
    builder.csi("?1049", b'l');
    for number in ["?1003", "?1002", "?1001", "?1000", "?9"] {
        builder.csi(number, b'l');
    }
    builder.csi("?1004", b'l');
    builder.csi("?2004", b'l');
    builder.csi("?2026", b'l');
    builder.raw(&[ESC, b'(', b'B']);
    builder.raw(&[ESC, b')', b'B']);
    builder.raw(&[0x0f]);
    builder.csi("0", b'm');
    builder.finish()
}

/// Whether this guest needs the size nudge (#494): only an alternate-screen one,
/// which cannot otherwise be made to redraw what the prompt erased.
pub(crate) fn nudges(screen: Screen) -> bool {
    matches!(screen, Screen::Alternate)
}

/// The result frame: everything from the status row down is replaced (§5.5).
///
/// If it does not fit, it is shortened to the sentence's first line plus a pointer
/// to `agent-vm access allowances` — that text is informational, not a choice, so
/// shortening it hides nothing a key could act on.
#[cfg(test)]
pub(crate) fn result(layout: &Layout, view: &ResultView) -> Vec<u8> {
    result_frame(layout.size, view)
}

/// The result frame, laid out from the terminal's geometry alone.
///
/// It replaced the whole screen, so it must not depend on whether the *question*
/// (with a grown waiting count) still fits: requiring that left a grant with no
/// frame, no deadline, and a takeover that never ended (M1/C-F1).
///
/// R20 promises the sentence, the command that undoes it and "Retry the request
/// now.". On a terminal too small for all of it the two actionable lines are kept
/// and the sentence's tail may not fit — but the frame then ends with a visible
/// pointer to `agent-vm access allowances` instead of stopping mid-sentence
/// silently (M11/C-F3).
pub(crate) fn result_frame(size: Size, view: &ResultView) -> Vec<u8> {
    if size.cols < MIN_COLS || size.rows < MIN_ROWS {
        // Below the size the takeover would ever have started at (R25): only a resize
        // can reach here, and nothing can be drawn. An empty frame is still a frame the
        // writer accepts, so the linger starts and the question restores.
        return Vec::new();
    }
    let width = usize::from(size.cols.saturating_sub(1));
    let rows_available = usize::from(size.rows);
    let mut sentence: Vec<String> = Vec::new();
    wrap(
        &crate::config::escape_str(&view.sentence),
        width,
        "  ",
        "  ",
        &mut sentence,
    );
    let mut tail: Vec<String> = Vec::new();
    if view.retry {
        wrap("Retry the request now.", width, "  ", "  ", &mut tail);
    }
    if let Some(undo) = &view.undo {
        wrap(
            &crate::config::escape_str(undo),
            width,
            "  ",
            "  ",
            &mut tail,
        );
    }
    // The actionable lines are reserved first, then one row says where the rest of the
    // sentence is: a truncation the user can see, never a silent stop (M11/C-F3).
    if sentence.len() + tail.len() > rows_available {
        let pointer = "  see agent-vm access allowances".to_owned();
        if tail.len() < rows_available {
            let room = rows_available - tail.len() - 1;
            sentence.truncate(room);
            sentence.push(pointer);
        } else {
            // Not even the pointer fits beside the actionable lines: they win, and
            // the last row says where the rest is.
            tail.truncate(rows_available);
            if let Some(last) = tail.last_mut() {
                *last = pointer;
            }
            sentence.clear();
        }
    }
    let mut rows = sentence;
    rows.extend(tail);
    let mut builder = Builder::new();
    for (row, text) in rows.iter().enumerate() {
        erase_row(&mut builder.0, row);
        builder.print(text);
    }
    for row in rows.len()..rows_available {
        erase_row(&mut builder.0, row);
    }
    builder.csi(&format!("{};3", size.rows), b'H');
    builder.finish()
}

#[cfg(test)]
mod tests;
