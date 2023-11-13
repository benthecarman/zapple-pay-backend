pub fn map_emoji(emoji: &str) -> Option<&str> {
    match emoji {
        "❤" | "+" | "" => Some("❤️"),
        "⚡️" => Some("⚡"),
        _ => None,
    }
}
