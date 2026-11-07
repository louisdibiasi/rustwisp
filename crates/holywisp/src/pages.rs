//! The built-in web client and the other canned HTTP bodies.

pub const WEBCLIENT_HTML: &str = include_str!("../../../examples/wisp-webclient.html");

/// The web client with `webclient-wisp-url` spliced into it (before `</head>`), or the page as
/// built when the URL is empty. The URL must already have passed [`check_wisp_url`].
pub fn webclient_page(url: &str) -> Result<Vec<u8>, String> {
    if url.is_empty() {
        return Ok(WEBCLIENT_HTML.as_bytes().to_vec());
    }
    let at = WEBCLIENT_HTML
        .find("</head>")
        .ok_or("web client has no </head> to inject into")?;
    let script = format!(
        "\t\t<script>\n\t\t\twindow.HOLYWISP_CONFIG = {{ wisp: \"{url}\" }};\n\t\t</script>\n\t"
    );
    let mut page = String::with_capacity(WEBCLIENT_HTML.len() + script.len());
    page.push_str(&WEBCLIENT_HTML[..at]);
    page.push_str(&script);
    page.push_str(&WEBCLIENT_HTML[at..]);
    Ok(page.into_bytes())
}

/// The URL goes into a `<script>` string literal: it must be ws:// or wss:// and contain nothing
/// that could end the literal or the element.
pub fn check_wisp_url(url: &str) -> Result<(), String> {
    if url.is_empty() {
        return Ok(());
    }
    if !url.starts_with("ws://") && !url.starts_with("wss://") {
        return Err("webclient-wisp-url must start with ws:// or wss://".into());
    }
    if url
        .bytes()
        .any(|b| b <= b' ' || matches!(b, b'"' | b'\'' | b'\\' | b'<' | b'>'))
    {
        return Err("webclient-wisp-url contains a character that cannot go into the page".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_the_url_before_head_end() {
        let page = String::from_utf8(webclient_page("wss://x.example/wisp/").unwrap()).unwrap();
        let script = page.find("HOLYWISP_CONFIG").unwrap();
        assert!(script < page.find("</head>").unwrap());
        assert!(page.contains("wss://x.example/wisp/"));
    }

    #[test]
    fn empty_url_serves_the_page_as_built() {
        assert_eq!(webclient_page("").unwrap(), WEBCLIENT_HTML.as_bytes());
    }

    #[test]
    fn rejects_urls_that_would_break_out_of_the_script() {
        assert!(check_wisp_url("http://x").is_err());
        assert!(check_wisp_url("wss://x\"</script>").is_err());
        assert!(check_wisp_url("wss://a b").is_err());
        assert!(check_wisp_url("wss://ok.example/wisp/").is_ok());
    }
}
