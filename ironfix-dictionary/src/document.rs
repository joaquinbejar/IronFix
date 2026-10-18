/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! What a dictionary document may hold outside its root element, checked
//! the same way by both loaders.
//!
//! XML 1.0 (sections 2.1 and 2.8) makes a document one root element with a
//! prolog before it and miscellany after it:
//!
//! ```text
//! document ::= prolog element Misc*
//! prolog   ::= XMLDecl? Misc* (doctypedecl Misc*)?
//! Misc     ::= Comment | PI | S
//! ```
//!
//! quick-xml reads one event at a time and does not enforce that shape: it
//! hands out text, CDATA sections, references and further elements after the
//! root as readily as inside it. Each loader therefore passes every event it
//! reads outside the root to [`Prolog::accept`] (before the root) or
//! [`epilog`] (after it), so a truncated, concatenated or corrupted
//! dictionary file is a [`DictionaryError::Xml`] rather than a dictionary
//! built from part of it.
//!
//! Accepted outside the root element:
//!
//! - whitespace (space, tab, carriage return, line feed: XML's `S`),
//!   comments and processing instructions, before and after it;
//! - the XML declaration, only as the first thing in the document (after a
//!   byte-order mark, which quick-xml strips). A declaration anywhere else,
//!   after the root above all, marks a second document appended to the
//!   first;
//! - one document type declaration, before the root. XML 1.0 allows it
//!   there, so rejecting it would refuse a well-formed file. It changes
//!   nothing the loaders read: quick-xml does not process a DTD, so an
//!   entity it declares is never expanded and an external subset is never
//!   fetched, and a reference to such an entity stays an error wherever a
//!   loader resolves references.
//!
//! Anything else is rejected: non-whitespace text, a CDATA section, a
//! character or entity reference, a second element, an XML declaration out
//! of place, a second document type declaration, or one after the root.

use crate::loader::DictionaryError;
use quick_xml::events::Event;

/// The longest excerpt of offending text or names an error quotes, in
/// characters.
const EXCERPT_CHARS: usize = 32;

/// Which side of the root element an event was read on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    /// In the prolog, before the root element.
    Before,
    /// After the root element.
    After,
}

impl Side {
    /// The word errors use for this side.
    #[must_use]
    const fn word(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
        }
    }
}

/// Checks the events of a prolog: everything before the root element.
#[derive(Debug, Default)]
pub(crate) struct Prolog {
    /// Whether an event has been read; the XML declaration must be the first.
    started: bool,
    /// Whether the document type declaration has been read.
    doctype: bool,
}

impl Prolog {
    /// Accepts `event`, read before the root element, if the prolog may hold
    /// it.
    ///
    /// The caller passes every event it reads before the root element's
    /// start tag, which it handles itself.
    ///
    /// # Errors
    /// Returns [`DictionaryError::Xml`] for non-whitespace text, a CDATA
    /// section, a reference, an XML declaration that is not the first event,
    /// a second document type declaration, an end tag, or the end of the
    /// document (no root element).
    pub(crate) fn accept(&mut self, event: &Event<'_>) -> Result<(), DictionaryError> {
        let first = !self.started;
        self.started = true;
        match event {
            Event::Decl(_) if first => Ok(()),
            Event::Decl(_) => Err(DictionaryError::Xml(
                "an XML declaration that does not start the document".to_owned(),
            )),
            Event::DocType(_) if self.doctype => Err(DictionaryError::Xml(
                "a second document type declaration".to_owned(),
            )),
            Event::DocType(_) => {
                self.doctype = true;
                Ok(())
            }
            Event::Eof => Err(DictionaryError::Xml("no root element".to_owned())),
            other => misc(other, Side::Before),
        }
    }
}

/// Accepts `event`, read after the root element, if XML allows it there:
/// whitespace, a comment, a processing instruction, or the end of the
/// document.
///
/// # Errors
/// Returns [`DictionaryError::Xml`] for anything else: non-whitespace text,
/// a CDATA section, a reference, a second element, an end tag, an XML
/// declaration or a document type declaration.
pub(crate) fn epilog(event: &Event<'_>) -> Result<(), DictionaryError> {
    match event {
        Event::Eof => Ok(()),
        other => misc(other, Side::After),
    }
}

/// Accepts `event` if it is `Misc` (whitespace, a comment or a processing
/// instruction), the only content XML allows on both sides of the root
/// element; rejects it, saying what it is and on which `side`, otherwise.
fn misc(event: &Event<'_>, side: Side) -> Result<(), DictionaryError> {
    let found = match event {
        Event::Comment(_) | Event::PI(_) | Event::Eof => return Ok(()),
        Event::Text(text) if text.chars().all(is_space) => return Ok(()),
        Event::Text(text) => format!("text `{}`", excerpt(text.trim_matches(is_space))),
        Event::CData(_) => "a CDATA section".to_owned(),
        Event::GeneralRef(reference) => format!("the reference `&{};`", excerpt(reference)),
        Event::Start(start) | Event::Empty(start) => {
            format!("an element <{}>", excerpt(start.name().0))
        }
        Event::End(end) => format!("an end tag </{}>", excerpt(end.name().0)),
        Event::Decl(_) => "an XML declaration".to_owned(),
        Event::DocType(_) => "a document type declaration".to_owned(),
    };
    Err(DictionaryError::Xml(format!(
        "{found} {} the root element",
        side.word()
    )))
}

/// Whether `c` is XML whitespace (`S`: space, tab, carriage return, line
/// feed); no other character is, a no-break space included.
#[must_use]
const fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

/// At most [`EXCERPT_CHARS`] characters of `text`, marked when cut, so an
/// error never copies more than that from the document.
#[must_use]
pub(crate) fn excerpt(text: &str) -> String {
    let mut chars = text.chars();
    let mut cut: String = chars.by_ref().take(EXCERPT_CHARS).collect();
    if chars.next().is_some() {
        cut.push_str("...");
    }
    cut
}

#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::Reader;

    /// Reads `xml` as a document with these checks, the way the loaders do,
    /// and returns the root element's name.
    fn read(xml: &str) -> Result<String, DictionaryError> {
        let xml_err = |e: quick_xml::Error| DictionaryError::Xml(e.to_string());
        let mut reader = Reader::from_str(xml);
        let mut prolog = Prolog::default();
        let (root, empty) = loop {
            match reader.read_event().map_err(xml_err)? {
                Event::Start(start) => break (start, false),
                Event::Empty(start) => break (start, true),
                event => prolog.accept(&event)?,
            }
        };
        let name = root.name().0.to_owned();
        if !empty {
            reader.read_to_end(root.name()).map_err(xml_err)?;
        }
        loop {
            match reader.read_event().map_err(xml_err)? {
                Event::Eof => return Ok(name),
                event => epilog(&event)?,
            }
        }
    }

    /// Returns the error `xml` is expected to be rejected with.
    #[track_caller]
    fn rejected(xml: &str) -> String {
        match read(xml) {
            Ok(root) => panic!("expected {xml:?} to be rejected, but read root <{root}>"),
            Err(DictionaryError::Xml(message)) => message,
            Err(other) => panic!("expected an XML error for {xml:?}, got {other:?}"),
        }
    }

    #[test]
    fn test_misc_on_both_sides_of_the_root_is_accepted() {
        let xml = "<?xml version='1.0' encoding='UTF-8'?>\r\n\
                   <!-- before -->\n<?pi before?>\n\
                   <!DOCTYPE root>\n<!-- after the doctype -->\t\n\
                   <root><inner>text &amp; more</inner></root>\n\
                   <!-- after -->\n<?pi after?>\n \t\r\n";
        assert!(matches!(read(xml), Ok(root) if root == "root"));
        assert!(matches!(read("<root/>"), Ok(root) if root == "root"));
        // A byte-order mark is not content: quick-xml strips it.
        assert!(read("\u{FEFF}<?xml version='1.0'?><root/>").is_ok());
    }

    #[test]
    fn test_content_after_the_root_is_rejected() {
        assert_eq!(
            rejected("<root/>TRAILING_CORRUPTION"),
            "text `TRAILING_CORRUPTION` after the root element"
        );
        assert_eq!(
            rejected("<root/>\n  junk \n"),
            "text `junk` after the root element"
        );
        assert_eq!(
            rejected("<root/><root/>"),
            "an element <root> after the root element"
        );
        assert_eq!(
            rejected("<root/><second></second>"),
            "an element <second> after the root element"
        );
        assert_eq!(
            rejected("<root/><![CDATA[x]]>"),
            "a CDATA section after the root element"
        );
        assert_eq!(
            rejected("<root/>&amp;"),
            "the reference `&amp;` after the root element"
        );
        // A character reference, even to whitespace, is not whitespace.
        assert_eq!(
            rejected("<root/>&#32;"),
            "the reference `&#32;` after the root element"
        );
        assert_eq!(
            rejected("<root/><?xml version='1.0'?><root/>"),
            "an XML declaration after the root element"
        );
        assert_eq!(
            rejected("<root/><!DOCTYPE root>"),
            "a document type declaration after the root element"
        );
        // A no-break space is not XML whitespace.
        assert_eq!(
            rejected("<root/>\n\u{A0}\n"),
            "text `\u{A0}` after the root element"
        );
    }

    #[test]
    fn test_content_before_the_root_is_rejected() {
        assert_eq!(
            rejected("JUNK<root/>"),
            "text `JUNK` before the root element"
        );
        assert_eq!(
            rejected("<?xml version='1.0'?>\nJUNK\n<root/>"),
            "text `JUNK` before the root element"
        );
        assert_eq!(
            rejected("<![CDATA[x]]><root/>"),
            "a CDATA section before the root element"
        );
        assert_eq!(
            rejected("&lt;<root/>"),
            "the reference `&lt;` before the root element"
        );
        assert_eq!(rejected(""), "no root element");
        assert_eq!(rejected("<!-- only a comment -->\n"), "no root element");
    }

    #[test]
    fn test_prolog_declarations_out_of_place_are_rejected() {
        let not_first = "an XML declaration that does not start the document";
        assert_eq!(rejected(" <?xml version='1.0'?><root/>"), not_first);
        assert_eq!(
            rejected("<!-- c --><?xml version='1.0'?><root/>"),
            not_first
        );
        assert_eq!(
            rejected("<?xml version='1.0'?><?xml version='1.0'?><root/>"),
            not_first
        );
        assert_eq!(
            rejected("<!DOCTYPE root><!DOCTYPE root><root/>"),
            "a second document type declaration"
        );
    }

    #[test]
    fn test_errors_quote_a_bounded_excerpt() {
        let long = "x".repeat(10 * EXCERPT_CHARS);
        let message = rejected(&format!("<root/>{long}"));
        let quoted = format!("{}...", "x".repeat(EXCERPT_CHARS));
        assert_eq!(message, format!("text `{quoted}` after the root element"));

        assert_eq!(excerpt("short"), "short");
        assert_eq!(excerpt(""), "");
        // Characters, not bytes: a multi-byte character is never split.
        let wide = "\u{e9}".repeat(EXCERPT_CHARS + 1);
        assert_eq!(
            excerpt(&wide),
            format!("{}...", "\u{e9}".repeat(EXCERPT_CHARS))
        );
    }
}
