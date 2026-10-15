use rand::seq::SliceRandom;

/// Terminal access used by the questionnaire (so the UI can supply its own fds).
pub trait Prompter {
    fn write(&mut self, s: &str);
    /// Reads one line without the terminator; `None` on EOF/error.
    fn read_line(&mut self) -> Option<String>;
}

fn ask(io: &mut dyn Prompter, prompt: &str, valid: &[&str], default: &str) -> String {
    io.write(prompt);
    let Some(input) = io.read_line() else {
        return default.to_string();
    };
    let trimmed = input.trim().to_lowercase();
    if valid.contains(&trimmed.as_str()) {
        trimmed
    } else {
        default.to_string()
    }
}

/// Generate a default username without interactive prompts.
#[cfg(test)]
pub fn generate_default_username() -> String {
    let base = choose_word("dark", "short");
    apply_transformation(&base, "subtle")
}

/// Interactive alias questionnaire over the given terminal.
pub fn generate_username_with(io: &mut dyn Prompter) -> String {

    io.write("\x1b[1;36m~~~~~~~~~~~~~~~~~~~~~~~~~~\x1b[0m\n");
    io.write("\x1b[1;36mQuestions for the user...\x1b[0m\n");
    io.write("\x1b[1;36m~~~~~~~~~~~~~~~~~~~~~~~~~~\x1b[0m\n\n");

    let _vibe = ask(
        io,
        "\x1b[1;32m1) What vibe do you want..??\x1b[0m\n  a) und3rgr0und hacker b) 6yberpunk/g1!tch c) M1n1mal @nd myst3ri0us\n  d) 0ld sch0o1 l33tspeak e) 3lite/cryptic\nEnter your choice (a/b/c/d/e): ",
        &["a", "b", "c", "d", "e"],
        "d",
    );

    let meaning = ask(
        io,
        "\x1b[1;32m2) What should be your name mean ..??\x1b[0m\n  a) Dark/Mysterious b) Rebellion/Chaos c) Techy/Code d) Space/Void/Null\n  e) abstract imagery f) Random meaning g) Depressed h) Suicidal\nEnter your choice (a/b/c/d/e/f/g/h): ",
        &["a", "b", "c", "d", "e", "f", "g", "h"],
        "a",
    );

    let mask = ask(
        io,
        "\x1b[1;32m3) How aggressively should characters be masked?\x1b[0m\n  a) Subtle b) Balanced c) Heavy d) Phonetic\nEnter your choice (a/b/c/d): ",
        &["a", "b", "c", "d"],
        "b",
    );

    let length = ask(
        io,
        "\x1b[1;32m4) Preferred Length\x1b[0m\n  a) Short (3-6 chars) b) Medium (7-12 chars) c) Long (13+ chars) d) Any length\nEnter your choice (a/b/c/d): ",
        &["a", "b", "c", "d"],
        "b",
    );

    let meaning_str = match meaning.as_str() {
        "a" => "dark",
        "b" => "chaos",
        "c" => "tech",
        "d" => "space",
        "e" => "abstract",
        "f" => "random",
        "g" => "depressed",
        "h" => "suicidal",
        _ => "dark",
    };

    let mask_str = match mask.as_str() {
        "a" => "subtle",
        "b" => "balanced",
        "c" => "heavy",
        "d" => "phonetic",
        _ => "balanced",
    };

    let length_str = match length.as_str() {
        "a" => "short",
        "b" => "medium",
        "c" => "long",
        "d" => "any",
        _ => "medium",
    };

    let base = choose_word(meaning_str, length_str);
    apply_transformation(&base, mask_str)
}

fn choose_word(meaning: &str, length_pref: &str) -> String {
    let mut rng = rand::thread_rng();

    let words_dark = [
        "dark", "shadow", "night", "demon", "ghost", "mystery", "obscure", "gloom", "shade",
        "phantom", "specter", "veil",
    ];
    let words_chaos = [
        "chaos",
        "rebellion",
        "riot",
        "havoc",
        "anarchy",
        "destruction",
        "disorder",
        "turmoil",
        "mayhem",
        "frenzy",
        "panic",
    ];
    let words_tech = [
        "tech", "computer", "code", "cyber", "glitch", "digital", "network", "hacker", "byte",
        "node", "wire", "logic", "hack", "proxy",
    ];
    let words_space = [
        "space", "void", "universe", "star", "cosmos", "galaxy", "abyss", "nebula", "planet",
        "orbit", "meteor", "comet",
    ];
    let words_abstract = [
        "abstract", "surreal", "dream", "illusion", "vision", "mirage", "enigma", "concept",
        "notion", "idea", "thought",
    ];
    let words_depressed = [
        "depression",
        "sadness",
        "grief",
        "melancholy",
        "sorrow",
        "despair",
        "misery",
        "woe",
        "agony",
        "pain",
    ];
    let words_suicidal = [
        "death", "end", "fatal", "doom", "perish", "oblivion", "ruin", "demise", "fate", "grave",
        "tomb",
    ];
    let words_random = [
        "apple", "stone", "fire", "ice", "wind", "earth", "water", "light", "time", "mind", "soul",
        "heart",
    ];

    let adjectives = [
        "silent",
        "lost",
        "broken",
        "forgotten",
        "hidden",
        "fallen",
        "cold",
        "blind",
        "dead",
        "empty",
        "hollow",
        "pale",
        "grim",
        "bleak",
        "stark",
    ];
    let nouns = [
        "walker", "seeker", "bringer", "soul", "mind", "eye", "hand", "voice", "face", "heart",
        "blood", "bone", "ash", "dust",
    ];

    let seeds = match meaning {
        "dark" => &words_dark[..],
        "chaos" => &words_chaos[..],
        "tech" => &words_tech[..],
        "space" => &words_space[..],
        "abstract" => &words_abstract[..],
        "depressed" => &words_depressed[..],
        "suicidal" => &words_suicidal[..],
        _ => &words_random[..],
    };

    let mut candidates = Vec::new();
    for &word in seeds {
        candidates.push(word.to_string());
        let adj = adjectives.choose(&mut rng).unwrap_or(&"silent");
        let noun = nouns.choose(&mut rng).unwrap_or(&"seeker");
        candidates.push(format!("{}{}", adj, word));
        candidates.push(format!("{}{}", word, noun));
        candidates.push(format!("{}{}{}", adj, word, noun));
    }

    let mut matching = Vec::new();
    for c in &candidates {
        let l = c.len();
        match length_pref {
            "short" if l <= 6 => matching.push(c.clone()),
            "medium" if (7..=12).contains(&l) => matching.push(c.clone()),
            "long" if l >= 13 => matching.push(c.clone()),
            "any" => matching.push(c.clone()),
            _ => {}
        }
    }

    if matching.is_empty() {
        let mut base = seeds.choose(&mut rng).unwrap_or(&"phantom").to_string();
        if length_pref == "short" && base.len() > 6 {
            base = base[..6].to_string();
        } else if length_pref == "medium" && base.len() < 7 {
            let adj = adjectives.choose(&mut rng).unwrap_or(&"silent");
            base = format!("{}{}", adj, base);
            if base.len() > 12 {
                base = base[..12].to_string();
            }
        } else if length_pref == "long" && base.len() < 13 {
            let adj = adjectives.choose(&mut rng).unwrap_or(&"silent");
            let noun = nouns.choose(&mut rng).unwrap_or(&"seeker");
            base = format!("{}{}{}", adj, base, noun);
        }
        base
    } else {
        matching
            .choose(&mut rng)
            .cloned()
            .unwrap_or_else(|| "ghost".to_string())
    }
}

fn apply_transformation(word: &str, mask_level: &str) -> String {
    let word = word.to_lowercase();
    let mut rng = rand::thread_rng();

    let transform_budget = match mask_level {
        "subtle" => std::cmp::max(1, word.len() / 4),
        "balanced" => std::cmp::max(2, word.len() / 2),
        "heavy" => std::cmp::max(3, (word.len() as f64 * 0.8) as usize),
        "phonetic" => word.len(),
        _ => word.len(),
    };

    let mut pool: Vec<usize> = if mask_level == "subtle" || mask_level == "balanced" {
        if word.len() > 1 {
            (1..word.len()).collect()
        } else {
            vec![0]
        }
    } else {
        (0..word.len()).collect()
    };
    pool.shuffle(&mut rng);
    let allowed: std::collections::HashSet<usize> =
        pool.into_iter().take(transform_budget).collect();

    let mut transformed = String::new();
    for (i, c) in word.chars().enumerate() {
        if !allowed.contains(&i) && mask_level != "phonetic" {
            transformed.push(c);
            continue;
        }

        match mask_level {
            "subtle" => {
                let replacements = match c {
                    'a' => vec!["4", "@", "^"],
                    'e' => vec!["3"],
                    'i' => vec!["1", "!"],
                    'o' => vec!["0"],
                    's' => vec!["5", "$"],
                    't' => vec!["7"],
                    _ => vec![],
                };
                if let Some(r) = replacements.choose(&mut rng) {
                    transformed.push_str(r);
                } else {
                    transformed.push(c);
                }
            }
            "balanced" => {
                transformed.push(match c {
                    'a' => '4',
                    'e' => '3',
                    'i' => '1',
                    'o' => '0',
                    's' => '5',
                    't' => '7',
                    _ => c,
                });
            }
            "heavy" => {
                transformed.push(match c {
                    'a' => '@',
                    'e' => '3',
                    'i' => '!',
                    'o' => '0',
                    's' => '$',
                    't' => '7',
                    'l' => '1',
                    'c' => '(',
                    _ => c,
                });
            }
            "phonetic" => {
                transformed.push(match c {
                    's' => 'z',
                    'f' => 'p',
                    'c' => 'k',
                    _ => c,
                });
            }
            _ => transformed.push(c),
        }
    }

    transformed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_choose_word_and_transform() {
        let word = choose_word("dark", "short");
        assert!(!word.is_empty());

        let transformed = apply_transformation(&word, "balanced");
        assert!(!transformed.is_empty());
    }

    struct Scripted {
        answers: Vec<&'static str>,
        written: String,
    }

    impl Prompter for Scripted {
        fn write(&mut self, s: &str) {
            self.written.push_str(s);
        }
        fn read_line(&mut self) -> Option<String> {
            if self.answers.is_empty() {
                None
            } else {
                Some(self.answers.remove(0).to_string())
            }
        }
    }

    #[test]
    fn questionnaire_uses_supplied_terminal_and_defaults_on_eof() {
        let mut io = Scripted { answers: vec!["a", "c", "d", "a"], written: String::new() };
        let alias = generate_username_with(&mut io);
        assert!(!alias.is_empty());
        assert!(io.written.contains("Questions for the user"));
        assert!(io.written.contains("Preferred Length"));

        let mut eof = Scripted { answers: vec![], written: String::new() };
        assert!(!generate_username_with(&mut eof).is_empty());
    }

    #[test]
    fn test_generate_username_produces_valid_alias() {
        let alias = generate_default_username();
        assert!(!alias.is_empty());
    }

    #[test]
    fn test_choose_word_all_meanings_and_lengths() {
        let meanings = [
            "dark",
            "chaos",
            "tech",
            "space",
            "abstract",
            "depressed",
            "suicidal",
            "unknown",
        ];
        let lengths = ["short", "medium", "long", "any", "other"];

        for meaning in meanings {
            for length in lengths {
                let word = choose_word(meaning, length);
                assert!(!word.is_empty());
            }
        }
    }

    #[test]
    fn test_apply_transformation_masks() {
        let masks = ["subtle", "balanced", "heavy", "phonetic", "passthrough"];
        let sample = "SilentShadowHacker123";

        for mask in masks {
            let res = apply_transformation(sample, mask);
            assert!(!res.is_empty());
        }
    }
}
