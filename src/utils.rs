use unicode_segmentation::UnicodeSegmentation;

pub fn valid_emoji_string(s: &str) -> bool {
    let graphemes = UnicodeSegmentation::graphemes(s, true);

    graphemes.count() == 1
}
