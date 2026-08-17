// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Pure, deterministic fact extraction for gated memory auto-capture.

use regex::Regex;
use std::sync::LazyLock;

/// A deterministic fact candidate extracted from a text blob.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractedFact {
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub date: Option<String>,
    pub confidence: f32,
    pub rule: &'static str,
}

/// Extraction profile — mirrors CruxEngine's `ExtractionProfile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractionProfile {
    Comprehensive,
    Money,
    Counts,
    Dates,
    VersionChains,
}

// SAFETY: every caller passes a compile-time-constant pattern. The comprehensive
// extraction tests initialise every static, so an invalid literal is caught in CI.
#[allow(clippy::expect_used)]
fn compile_regex(pattern: &str) -> Regex {
    Regex::new(pattern).expect("static memory-extraction regex must compile")
}

static MONEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        r"(\$\s*[0-9][0-9,]*(?:\.[0-9]+)?(?:[kK]|[mM])?)|([0-9][0-9,]*(?:\.[0-9]+)?\s*(?:dollars?|USD|GBP|EUR|€|£))",
    )
});
static ISO_DATE_RE: LazyLock<Regex> =
    LazyLock::new(|| compile_regex(r"(?-u:\b)(20[12][0-9])-([0-9]{2})-([0-9]{2})(?-u:\b)"));
static MONTH_DAY_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        r"(?-u:\b)(January|February|March|April|May|June|July|August|September|October|November|December)\s+([0-9]{1,2})(?:st|nd|rd|th)?(?:,\s*([0-9]{4}))?",
    )
});
static COUNT_ITEM_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        r"(?i)(?-u:\b)([0-9]+|zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|dozen)\s+(plant|plants|bike|bikes|car|cars|pet|pets|cat|cats|dog|dogs|book|books|project|projects|city|cities|country|countries|friend|friends|colleague|colleagues|child|children|kid|kids|tool|tools|instrument|instruments|shirt|shirts|pair|pairs|item|items|bottle|bottles)(?-u:\b)",
    )
});
static PROJECT_PRED_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        r"(?-u:\b)(I|currently|now|I'?m)?\s*(led|leading|manage|managing|managed|oversees|running|ran|launched|launching|head|heading|headed|own|owns|owned|drive|driving|drove|direct|directed|directing|building|working on)\s+(?:a|an|the|my)?\s*([A-Z][-A-Za-z0-9 ']{3,40}(?:project|launch|initiative|team|rollout|program))(?-u:\b)",
    )
});
static ACQUIRE_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        r"(?-u:\b)(bought|acquired|purchased|got|received|picked up|added)\s+(?:a|an|the|some|[0-9]+)\s+([a-zA-Z][A-Za-z0-9_\s]{2,40})",
    )
});
static VERSION_CHAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        r"(?i)(?-u:\b)(?:used to|previously|before)\s+(?:[a-z\s]+\s+)?(?:was|be|have|had|had been)\s+([^.]{3,60})(?-u:\b)",
    )
});
static CURRENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        r"(?i)(?-u:\b)(?:currently|now|these days|at the moment)\s+(?:I\s+)?(?:[a-z]+\s+)?(?:is|am|have|has|work)\s*(?:as|at|for|in)?\s*([^.]{3,60})(?-u:\b)",
    )
});

// Rust's regex engine has no look-around. These four patterns consume and discard
// the boundary that the TypeScript expressions asserted with a lookahead; capture
// group 1 remains the clause value.
static PREVIOUS_ROLE_AS_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        r"(?i)(?-u:\b)in\s+my\s+previous\s+(?:role|job)\s+as\s+(?:a|an\s+)?([^.!,;]+?)(?:\s+(?:and|where|but|while|with)(?-u:\b)|[.!?,;]|$)",
    )
});
static BEFORE_THIS_ROLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        r"(?i)(?-u:\b)before\s+this[, ]+\s*i\s+(?:was|worked)\s+(?:as\s+)?(?:a|an\s+)?([^.!,;]+?)(?:\s+(?:and|but|while)(?-u:\b)|[.!?,;]|$)",
    )
});
static PREVIOUS_OCCUPATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        r"(?i)(?-u:\b)my\s+previous\s+occupation\s+(?:was|is)\s+(?:a|an\s+)?([^.!,;]+?)(?:\s+(?:and|but|while)(?-u:\b)|[.!?,;]|$)",
    )
});
static USED_TO_BE_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        r"(?i)(?-u:\b)i\s+used\s+to\s+be\s+(?:a|an\s+)?([^.!,;]+?)(?:\s+(?:but|and|before|now|currently)(?-u:\b)|[.!?,;]|$)",
    )
});

static FAMILY_TRIP_TO_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        r"(?-u:\b)(?:my|My|our|Our)\s+(?:recent|Recent|last|Last|most recent|Most recent)\s+family\s+(?:trip|vacation|holiday)\s+to\s+([A-Z][A-Za-z.'-]*(?:\s+[A-Z][A-Za-z.'-]*){0,3})",
    )
});
static FAMILY_WENT_TO_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        r"(?-u:\b)(?:we|We)\s+just\s+went\s+to\s+([A-Z][A-Za-z.'-]*(?:\s+[A-Z][A-Za-z.'-]*){0,3})\s+as\s+a\s+family(?-u:\b)",
    )
});
static FAMILY_WENT_THERE_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        r"(?-u:\b)(?:thinking\s+of\s+going\s+to|Thinking\s+of\s+going\s+to|going\s+to|Going\s+to)\s+([A-Z][A-Za-z.'-]*(?:\s+[A-Z][A-Za-z.'-]*){0,3}),\s+(?:we|We)\s+just\s+went\s+there\s+as\s+a\s+family(?-u:\b)",
    )
});
static FAMILY_SIMPLE_WENT_TO_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        r"(?-u:\b)(?:the|The)\s+family\s+went\s+to\s+([A-Z][A-Za-z.'-]*(?:\s+[A-Z][A-Za-z.'-]*){0,3})(?:\s+(?:and|where|but|while|with)(?-u:\b)|(?:\s+[^.!,;]+)?(?:[.!?,;]|$))",
    )
});

static FENCED_CODE_RE: LazyLock<Regex> = LazyLock::new(|| compile_regex(r"(?s)```.*?```"));
static URL_RE: LazyLock<Regex> = LazyLock::new(|| compile_regex(r"https?://\S+"));
static WHITESPACE_RE: LazyLock<Regex> = LazyLock::new(|| compile_regex(r"\s+"));
static CLAUSE_EDGE_RE: LazyLock<Regex> = LazyLock::new(|| compile_regex(r#"^[\s"'`]+|[\s"'`]+$"#));
static LEADING_ARTICLE_RE: LazyLock<Regex> = LazyLock::new(|| compile_regex(r"(?i)^(?:a|an)\s+"));
static OCCUPATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        r"(?i)(?-u:\b)(analyst|architect|assistant|consultant|coordinator|designer|developer|director|doctor|editor|engineer|freelancer|intern|manager|marketer|marketing|nurse|paramedic|producer|professor|researcher|sales|specialist|strategist|teacher|writer|worked at|at\s+[A-Z]|startup)(?-u:\b)",
    )
});

/// Strip fenced code blocks and URLs before extraction.
pub fn scrub_noise(text: &str) -> String {
    let without_fences = FENCED_CODE_RE.replace_all(text, " ");
    URL_RE.replace_all(&without_fences, " ").into_owned()
}

fn normalise_money(value: &str) -> String {
    let mut compact: String = value
        .chars()
        .filter(|c| c.is_ascii_digit() || matches!(c, '.' | 'k' | 'K' | 'm' | 'M'))
        .collect();
    let exponent = match compact.chars().next_back() {
        Some('k' | 'K') => 3,
        Some('m' | 'M') => 6,
        _ => return compact,
    };
    let _ = compact.pop();
    scale_decimal(&compact, exponent)
}

fn scale_decimal(value: &str, exponent: usize) -> String {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    let decimal_index = whole.len() + exponent;
    let mut digits = String::with_capacity(decimal_index.max(value.len()));
    digits.push_str(whole);
    digits.push_str(fraction);

    if digits.len() <= decimal_index {
        digits.extend(std::iter::repeat_n('0', decimal_index - digits.len()));
        return digits;
    }

    digits.insert(decimal_index, '.');
    while digits.ends_with('0') {
        let _ = digits.pop();
    }
    if digits.ends_with('.') {
        let _ = digits.pop();
    }
    digits
}

fn push_unique(out: &mut Vec<ExtractedFact>, fact: ExtractedFact) -> bool {
    let duplicate = out.iter().any(|existing| {
        existing.subject == fact.subject
            && existing.predicate == fact.predicate
            && existing.object.to_lowercase() == fact.object.to_lowercase()
    });
    if duplicate {
        false
    } else {
        out.push(fact);
        true
    }
}

fn clean_clause_value(value: &str) -> String {
    let collapsed = WHITESPACE_RE.replace_all(value, " ");
    let unquoted = CLAUSE_EDGE_RE.replace_all(&collapsed, "");
    LEADING_ARTICLE_RE.replace(&unquoted, "").trim().to_owned()
}

fn looks_like_occupation(value: &str) -> bool {
    OCCUPATION_RE.is_match(value)
}

fn truncate_chars(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

fn context_window(text: &str, match_start: usize, match_end: usize, radius: usize) -> &str {
    let mut start = match_start;
    for (byte_index, _) in text[..match_start].char_indices().rev().take(radius) {
        start = byte_index;
    }

    let mut end = match_end;
    for (relative_index, ch) in text[match_end..].char_indices().take(radius) {
        end = match_end + relative_index + ch.len_utf8();
    }
    &text[start..end]
}

fn money_predicate(context: &str) -> &'static str {
    let context = WHITESPACE_RE.replace_all(context, " ").to_lowercase();
    if context.contains("pre-approv") || context.contains("pre approv") || context.contains("preapprov") {
        "loan_pre_approval_amount"
    } else if context.contains("mortgage") {
        "mortgage_amount"
    } else if context.contains("spent") || context.contains("paid") || context.contains("cost") {
        "spent"
    } else if context.contains("salary")
        || context.contains("earn")
        || context.contains("make")
        || context.contains("income")
    {
        "salary"
    } else {
        "mentioned_amount"
    }
}

fn word_number(value: &str) -> Option<u8> {
    match value {
        "zero" => Some(0),
        "one" => Some(1),
        "two" => Some(2),
        "three" => Some(3),
        "four" => Some(4),
        "five" => Some(5),
        "six" => Some(6),
        "seven" => Some(7),
        "eight" => Some(8),
        "nine" => Some(9),
        "ten" => Some(10),
        "eleven" => Some(11),
        "twelve" | "dozen" => Some(12),
        _ => None,
    }
}

fn normalise_count(value: &str) -> Option<String> {
    if value.bytes().all(|byte| byte.is_ascii_digit()) {
        let without_zeroes = value.trim_start_matches('0');
        Some(if without_zeroes.is_empty() {
            "0".to_owned()
        } else {
            without_zeroes.to_owned()
        })
    } else {
        word_number(value).map(|number| number.to_string())
    }
}

fn singular_item(item: &str) -> &str {
    match item {
        "cities" => "city",
        "countries" => "country",
        "children" => "child",
        _ => item.strip_suffix('s').unwrap_or(item),
    }
}

fn month_number(month: &str) -> Option<u8> {
    match month {
        "January" => Some(1),
        "February" => Some(2),
        "March" => Some(3),
        "April" => Some(4),
        "May" => Some(5),
        "June" => Some(6),
        "July" => Some(7),
        "August" => Some(8),
        "September" => Some(9),
        "October" => Some(10),
        "November" => Some(11),
        "December" => Some(12),
        _ => None,
    }
}

fn session_year(session_date: Option<&str>) -> Option<&str> {
    let date = session_date?;
    let year = date.get(..4)?;
    year.bytes().all(|byte| byte.is_ascii_digit()).then_some(year)
}

fn run_money_rule(text: &str, out: &mut Vec<ExtractedFact>) {
    for matched in MONEY_RE.find_iter(text) {
        let context = context_window(text, matched.start(), matched.end(), 40);
        push_unique(
            out,
            ExtractedFact {
                subject: "user".to_owned(),
                predicate: money_predicate(context).to_owned(),
                object: normalise_money(matched.as_str()),
                date: None,
                confidence: 0.85,
                rule: "money",
            },
        );
    }
}

fn run_count_rule(text: &str, out: &mut Vec<ExtractedFact>) {
    for captures in COUNT_ITEM_RE.captures_iter(text) {
        let (Some(number), Some(item)) = (captures.get(1), captures.get(2)) else {
            continue;
        };
        let number = number.as_str().to_lowercase();
        let Some(number) = normalise_count(&number) else {
            continue;
        };
        let item = item.as_str().to_lowercase();
        push_unique(
            out,
            ExtractedFact {
                subject: "user".to_owned(),
                predicate: format!("owns_{}_count", singular_item(&item)),
                object: number,
                date: None,
                confidence: 0.80,
                rule: "count_item",
            },
        );
    }
}

fn run_date_rule(text: &str, session_date: Option<&str>, out: &mut Vec<ExtractedFact>) {
    for matched in ISO_DATE_RE.find_iter(text) {
        let date = matched.as_str().to_owned();
        push_unique(
            out,
            ExtractedFact {
                subject: "user".to_owned(),
                predicate: "mentioned_date".to_owned(),
                object: date.clone(),
                date: Some(date),
                confidence: 0.90,
                rule: "date_iso",
            },
        );
    }

    for captures in MONTH_DAY_RE.captures_iter(text) {
        let (Some(month), Some(day)) = (captures.get(1), captures.get(2)) else {
            continue;
        };
        let Some(month_number) = month_number(month.as_str()) else {
            continue;
        };
        let Ok(day_number) = day.as_str().parse::<u8>() else {
            continue;
        };
        let year = captures
            .get(3)
            .map(|matched| matched.as_str())
            .or_else(|| session_year(session_date));
        let Some(year) = year else {
            continue;
        };
        let date = format!("{year}-{month_number:02}-{day_number:02}");
        push_unique(
            out,
            ExtractedFact {
                subject: "user".to_owned(),
                predicate: "mentioned_date".to_owned(),
                object: date.clone(),
                date: Some(date),
                confidence: 0.82,
                rule: "date_month_day",
            },
        );
    }
}

fn run_project_rule(text: &str, out: &mut Vec<ExtractedFact>) {
    for captures in PROJECT_PRED_RE.captures_iter(text) {
        let (Some(verb), Some(name)) = (captures.get(2), captures.get(3)) else {
            continue;
        };
        let verb = verb.as_str().to_lowercase();
        let predicate_verb = WHITESPACE_RE.replace_all(&verb, "_");
        let name = name.as_str().trim();
        if name.is_empty() {
            continue;
        }
        push_unique(
            out,
            ExtractedFact {
                subject: "user".to_owned(),
                predicate: format!("{predicate_verb}_project"),
                object: name.to_owned(),
                date: None,
                confidence: 0.70,
                rule: "project_pred",
            },
        );
    }
}

fn run_acquire_rule(text: &str, session_date: Option<&str>, out: &mut Vec<ExtractedFact>) {
    for captures in ACQUIRE_RE.captures_iter(text) {
        let (Some(verb), Some(object)) = (captures.get(1), captures.get(2)) else {
            continue;
        };
        let verb = verb.as_str().to_lowercase();
        let object = truncate_chars(object.as_str().trim(), 40);
        push_unique(
            out,
            ExtractedFact {
                subject: "user".to_owned(),
                predicate: if verb == "picked up" {
                    "acquired".to_owned()
                } else {
                    verb
                },
                object,
                date: session_date.map(str::to_owned),
                confidence: 0.72,
                rule: "acquire",
            },
        );
    }
}

fn run_previous_occupation_rule(text: &str, out: &mut Vec<ExtractedFact>) {
    if out
        .iter()
        .any(|fact| fact.subject == "user" && fact.predicate == "previous_occupation")
    {
        return;
    }

    let patterns: [&Regex; 4] = [
        &PREVIOUS_ROLE_AS_RE,
        &BEFORE_THIS_ROLE_RE,
        &PREVIOUS_OCCUPATION_RE,
        &USED_TO_BE_RE,
    ];
    for pattern in patterns {
        for captures in pattern.captures_iter(text) {
            let Some(capture) = captures.get(1) else {
                continue;
            };
            let occupation = truncate_chars(&clean_clause_value(capture.as_str()), 120);
            if occupation.is_empty() || !looks_like_occupation(&occupation) {
                continue;
            }
            if push_unique(
                out,
                ExtractedFact {
                    subject: "user".to_owned(),
                    predicate: "previous_occupation".to_owned(),
                    object: occupation,
                    date: None,
                    confidence: 0.83,
                    rule: "previous_occupation",
                },
            ) {
                return;
            }
        }
    }
}

fn run_family_trip_destination_rule(text: &str, out: &mut Vec<ExtractedFact>) {
    if out
        .iter()
        .any(|fact| fact.subject == "user" && fact.predicate == "family_trip_destination")
    {
        return;
    }

    let patterns: [&Regex; 4] = [
        &FAMILY_TRIP_TO_RE,
        &FAMILY_WENT_TO_RE,
        &FAMILY_WENT_THERE_RE,
        &FAMILY_SIMPLE_WENT_TO_RE,
    ];
    for pattern in patterns {
        for captures in pattern.captures_iter(text) {
            let Some(capture) = captures.get(1) else {
                continue;
            };
            let destination = truncate_chars(&clean_clause_value(capture.as_str()), 80);
            if destination.is_empty() {
                continue;
            }
            if push_unique(
                out,
                ExtractedFact {
                    subject: "user".to_owned(),
                    predicate: "family_trip_destination".to_owned(),
                    object: destination,
                    date: None,
                    confidence: 0.82,
                    rule: "family_trip_destination",
                },
            ) {
                return;
            }
        }
    }
}

fn run_version_rule(text: &str, out: &mut Vec<ExtractedFact>) {
    for captures in VERSION_CHAIN_RE.captures_iter(text) {
        let Some(object) = captures.get(1) else {
            continue;
        };
        push_unique(
            out,
            ExtractedFact {
                subject: "user".to_owned(),
                predicate: "previously".to_owned(),
                object: truncate_chars(object.as_str().trim(), 60),
                date: None,
                confidence: 0.70,
                rule: "version_previous",
            },
        );
    }

    for captures in CURRENT_RE.captures_iter(text) {
        let Some(object) = captures.get(1) else {
            continue;
        };
        push_unique(
            out,
            ExtractedFact {
                subject: "user".to_owned(),
                predicate: "currently".to_owned(),
                object: truncate_chars(object.as_str().trim(), 60),
                date: None,
                confidence: 0.72,
                rule: "version_current",
            },
        );
    }
}

/// Extract facts from one text blob using the selected deterministic profile.
///
/// `session_date` supplies the year for month-day dates that omit one, and is
/// copied onto acquisition facts to mirror the source rule.
pub fn extract_facts_from_text(
    text: &str,
    profile: &ExtractionProfile,
    session_date: Option<&str>,
) -> Vec<ExtractedFact> {
    let text = scrub_noise(text);
    let mut facts = Vec::new();

    match profile {
        ExtractionProfile::Comprehensive => {
            run_money_rule(&text, &mut facts);
            run_count_rule(&text, &mut facts);
            run_date_rule(&text, session_date, &mut facts);
            run_project_rule(&text, &mut facts);
            run_acquire_rule(&text, session_date, &mut facts);
            run_previous_occupation_rule(&text, &mut facts);
            run_family_trip_destination_rule(&text, &mut facts);
            run_version_rule(&text, &mut facts);
        }
        ExtractionProfile::Money => run_money_rule(&text, &mut facts),
        ExtractionProfile::Counts => run_count_rule(&text, &mut facts),
        ExtractionProfile::Dates => run_date_rule(&text, session_date, &mut facts),
        ExtractionProfile::VersionChains => {
            run_previous_occupation_rule(&text, &mut facts);
            run_family_trip_destination_rule(&text, &mut facts);
            run_version_rule(&text, &mut facts);
        }
    }

    facts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_only_fact(
        text: &str,
        profile: ExtractionProfile,
        session_date: Option<&str>,
        expected: (&str, &str, Option<&str>, f32, &str),
    ) {
        let (predicate, object, date, confidence, rule) = expected;
        let facts = extract_facts_from_text(text, &profile, session_date);
        assert_eq!(facts.len(), 1, "unexpected facts: {facts:#?}");
        assert_eq!(facts[0].subject, "user");
        assert_eq!(facts[0].predicate, predicate);
        assert_eq!(facts[0].object, object);
        assert_eq!(facts[0].date.as_deref(), date);
        assert_eq!(facts[0].confidence.to_bits(), confidence.to_bits());
        assert_eq!(facts[0].rule, rule);
    }

    #[test]
    fn money_extracts_pre_approval_amount() {
        assert_only_fact(
            "My mortgage pre-approval was $450,000.",
            ExtractionProfile::Comprehensive,
            None,
            ("loan_pre_approval_amount", "450000", None, 0.85, "money"),
        );
    }

    #[test]
    fn money_expands_suffix_and_accepts_unhyphenated_context() {
        assert_only_fact(
            "I was preapproved for $1.2M.",
            ExtractionProfile::Money,
            None,
            ("loan_pre_approval_amount", "1200000", None, 0.85, "money"),
        );
    }

    #[test]
    fn count_item_extracts_word_number_and_singular_item() {
        assert_only_fact(
            "I have three cats.",
            ExtractionProfile::Comprehensive,
            None,
            ("owns_cat_count", "3", None, 0.80, "count_item"),
        );
    }

    #[test]
    fn date_iso_extracts_iso_date() {
        assert_only_fact(
            "The appointment is on 2024-03-05.",
            ExtractionProfile::Comprehensive,
            None,
            ("mentioned_date", "2024-03-05", Some("2024-03-05"), 0.90, "date_iso"),
        );
    }

    #[test]
    fn date_month_day_normalises_with_explicit_year() {
        assert_only_fact(
            "The appointment is March 5th, 2024.",
            ExtractionProfile::Comprehensive,
            None,
            (
                "mentioned_date",
                "2024-03-05",
                Some("2024-03-05"),
                0.82,
                "date_month_day",
            ),
        );
    }

    #[test]
    fn project_pred_extracts_verb_and_project_name() {
        assert_only_fact(
            "I'm leading the Apollo Migration project.",
            ExtractionProfile::Comprehensive,
            None,
            (
                "leading_project",
                "Apollo Migration project",
                None,
                0.70,
                "project_pred",
            ),
        );
    }

    #[test]
    fn project_pred_snake_cases_multiword_hint() {
        assert_only_fact(
            "I'm working on the Atlas Search project.",
            ExtractionProfile::Comprehensive,
            None,
            ("working_on_project", "Atlas Search project", None, 0.70, "project_pred"),
        );
    }

    #[test]
    fn acquire_extracts_object_and_session_date() {
        assert_only_fact(
            "I picked up a vintage bicycle.",
            ExtractionProfile::Comprehensive,
            Some("2026-07-14"),
            ("acquired", "vintage bicycle", Some("2026-07-14"), 0.72, "acquire"),
        );
    }

    #[test]
    fn version_previous_extracts_prior_value() {
        assert_only_fact(
            "I previously was a Windows user.",
            ExtractionProfile::Comprehensive,
            None,
            ("previously", "a Windows user", None, 0.70, "version_previous"),
        );
    }

    #[test]
    fn version_current_extracts_current_value() {
        assert_only_fact(
            "Currently I am based in Bristol.",
            ExtractionProfile::Comprehensive,
            None,
            ("currently", "based in Bristol", None, 0.72, "version_current"),
        );
    }

    #[test]
    fn previous_occupation_extracts_and_cleans_clause() {
        assert_only_fact(
            "In my previous role as a paramedic and later trained recruits.",
            ExtractionProfile::Comprehensive,
            None,
            ("previous_occupation", "paramedic", None, 0.83, "previous_occupation"),
        );
    }

    #[test]
    fn family_trip_destination_extracts_destination() {
        assert_only_fact(
            "The family went to Portugal last summer.",
            ExtractionProfile::Comprehensive,
            None,
            (
                "family_trip_destination",
                "Portugal",
                None,
                0.82,
                "family_trip_destination",
            ),
        );
    }

    #[test]
    fn family_trip_destination_preserves_source_pattern() {
        assert_only_fact(
            "Our recent family trip to Portugal was restorative.",
            ExtractionProfile::Comprehensive,
            None,
            (
                "family_trip_destination",
                "Portugal",
                None,
                0.82,
                "family_trip_destination",
            ),
        );
    }

    #[test]
    fn scrub_noise_strips_fenced_code_and_urls() {
        let scrubbed = scrub_noise("Keep ```const date = '2024-03-05';``` this https://example.com/$900 end");
        assert_eq!(scrubbed, "Keep   this   end");
        assert!(!scrubbed.contains("2024-03-05"));
        assert!(!scrubbed.contains("https://"));
    }

    #[test]
    fn extraction_deduplicates_repeated_facts() {
        let facts = extract_facts_from_text("I paid $20. I paid $20.", &ExtractionProfile::Comprehensive, None);
        assert_eq!(facts.len(), 1, "unexpected facts: {facts:#?}");
        assert_eq!(facts[0].predicate, "spent");
        assert_eq!(facts[0].object, "20");
    }

    #[test]
    fn no_extractable_fact_returns_empty() {
        let facts = extract_facts_from_text(
            "The quick brown fox considers an ordinary afternoon.",
            &ExtractionProfile::Comprehensive,
            None,
        );
        assert!(facts.is_empty(), "unexpected facts: {facts:#?}");
    }

    #[test]
    fn month_day_uses_session_year_and_skips_unknown_year() {
        assert_only_fact(
            "The appointment is March 5th.",
            ExtractionProfile::Dates,
            Some("2026-07-14"),
            (
                "mentioned_date",
                "2026-03-05",
                Some("2026-03-05"),
                0.82,
                "date_month_day",
            ),
        );

        let without_year = extract_facts_from_text("The appointment is March 5th.", &ExtractionProfile::Dates, None);
        assert!(without_year.is_empty(), "unexpected facts: {without_year:#?}");
    }

    #[test]
    fn profiles_gate_rule_families() {
        let text = "I paid $20, have two cars, and met them on 2024-03-05.";
        let money = extract_facts_from_text(text, &ExtractionProfile::Money, None);
        let counts = extract_facts_from_text(text, &ExtractionProfile::Counts, None);
        let dates = extract_facts_from_text(text, &ExtractionProfile::Dates, None);
        let versions = extract_facts_from_text(text, &ExtractionProfile::VersionChains, None);

        assert_eq!(money.len(), 1);
        assert_eq!(money[0].rule, "money");
        assert_eq!(counts.len(), 1);
        assert_eq!(counts[0].rule, "count_item");
        assert_eq!(dates.len(), 1);
        assert_eq!(dates[0].rule, "date_iso");
        assert!(versions.is_empty(), "unexpected facts: {versions:#?}");
    }

    #[test]
    fn occupation_and_family_rules_emit_at_most_one_each() {
        let text = "In my previous role as a teacher, I taught maths. My previous occupation was an engineer. The family went to Portugal, and our recent family trip to Spain was relaxing.";
        let facts = extract_facts_from_text(text, &ExtractionProfile::VersionChains, None);
        let occupation_count = facts.iter().filter(|fact| fact.rule == "previous_occupation").count();
        let destination_count = facts
            .iter()
            .filter(|fact| fact.rule == "family_trip_destination")
            .count();

        assert_eq!(occupation_count, 1);
        assert_eq!(destination_count, 1);
    }
}
