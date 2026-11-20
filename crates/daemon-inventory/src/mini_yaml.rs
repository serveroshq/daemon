//! Just enough YAML to read Traefik's config files: nested maps, lists of
//! scalars or maps, quoted and plain scalars, `[a, b]` lists and comments.
//! Anchors, multi-line strings and the rest of YAML read as nothing, which
//! is fine for the few keys ServerOS looks at.

use serde_json::{Map, Value};

struct Line<'a> {
    indent: usize,
    text: &'a str,
}

/// The document as JSON, or Null when it doesn't read.
pub fn parse(text: &str) -> Value {
    let lines: Vec<Line> = text
        .lines()
        .filter_map(|raw| {
            let text = strip_comment(raw).trim_end();
            let trimmed = text.trim_start();
            if trimmed.is_empty() || trimmed == "---" || trimmed == "..." {
                return None;
            }
            Some(Line {
                indent: text.len() - trimmed.len(),
                text: trimmed,
            })
        })
        .collect();
    let mut at = 0;
    block(&lines, &mut at, 0)
}

fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut previous = ' ';
    for (i, c) in line.char_indices() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == '#' && (previous == ' ' || i == 0) => return &line[..i],
            None => {}
        }
        previous = c;
    }
    line
}

fn block(lines: &[Line], at: &mut usize, indent: usize) -> Value {
    let Some(first) = lines.get(*at) else {
        return Value::Null;
    };
    if first.indent < indent {
        return Value::Null;
    }
    let indent = first.indent;
    if first.text.starts_with("- ") || first.text == "-" {
        let mut list = Vec::new();
        while let Some(line) = lines.get(*at) {
            if line.indent != indent || !(line.text.starts_with("- ") || line.text == "-") {
                break;
            }
            let rest = line.text[1..].trim_start();
            *at += 1;
            if rest.is_empty() {
                list.push(block(lines, at, indent + 1));
            } else if let Some((key, value)) = key_value(rest) {
                // `- key: value` and the keys under it.
                let mut map = Map::new();
                let inner = indent + 2;
                insert(&mut map, key, value, lines, at, inner);
                while let Some(next) = lines.get(*at) {
                    if next.indent != inner || next.text.starts_with("- ") {
                        break;
                    }
                    let Some((key, value)) = key_value(next.text) else {
                        break;
                    };
                    *at += 1;
                    insert(&mut map, key, value, lines, at, inner);
                }
                list.push(Value::Object(map));
            } else {
                list.push(scalar(rest));
            }
        }
        return Value::Array(list);
    }
    let mut map = Map::new();
    while let Some(line) = lines.get(*at) {
        if line.indent != indent {
            if line.indent > indent {
                // Something we don't read: skip it.
                *at += 1;
                continue;
            }
            break;
        }
        let Some((key, value)) = key_value(line.text) else {
            *at += 1;
            continue;
        };
        *at += 1;
        insert(&mut map, key, value, lines, at, indent);
    }
    Value::Object(map)
}

fn insert(
    map: &mut Map<String, Value>,
    key: String,
    value: &str,
    lines: &[Line],
    at: &mut usize,
    indent: usize,
) {
    let value = if value.is_empty() {
        match lines.get(*at) {
            Some(next) if next.indent > indent => block(lines, at, indent + 1),
            // A list may sit at the same indent as its key.
            Some(next) if next.indent == indent && next.text.starts_with("- ") => {
                block(lines, at, indent)
            }
            _ => Value::Null,
        }
    } else if value.starts_with('|') || value.starts_with('>') {
        while lines.get(*at).is_some_and(|l| l.indent > indent) {
            *at += 1;
        }
        Value::Null
    } else {
        scalar(value)
    };
    map.insert(key, value);
}

/// `key: value` or `key:`, with the key unquoted.
fn key_value(text: &str) -> Option<(String, &str)> {
    let (key, rest) = if let Some(quoted) = text.strip_prefix('"') {
        let end = quoted.find('"')?;
        (&quoted[..end], quoted[end + 1..].strip_prefix(':')?)
    } else if let Some(quoted) = text.strip_prefix('\'') {
        let end = quoted.find('\'')?;
        (&quoted[..end], quoted[end + 1..].strip_prefix(':')?)
    } else {
        let colon = text
            .find(": ")
            .or_else(|| text.strip_suffix(':').map(|t| t.len()))?;
        (&text[..colon], &text[colon + 1..])
    };
    Some((key.trim().to_string(), rest.trim()))
}

fn scalar(text: &str) -> Value {
    let text = text.trim();
    if let Some(inner) = text.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        return Value::Array(
            inner
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(scalar)
                .collect(),
        );
    }
    if let Some(inner) = text.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
        return Value::String(inner.replace("\\\"", "\"").replace("\\\\", "\\"));
    }
    if let Some(inner) = text.strip_prefix('\'').and_then(|t| t.strip_suffix('\'')) {
        return Value::String(inner.replace("''", "'"));
    }
    match text {
        "true" | "True" | "TRUE" => Value::Bool(true),
        "false" | "False" | "FALSE" => Value::Bool(false),
        "null" | "~" => Value::Null,
        _ => text
            .parse::<i64>()
            .map(Value::from)
            .unwrap_or_else(|_| Value::String(text.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_traefik_static_and_dynamic_config() {
        let text = r#"
# Static config
entryPoints:
  web:
    address: ":80"   # plain
  websecure:
    address: ":443"
api:
  insecure: true
accessLog:
  filePath: "/var/log/traefik/access.log"
  format: json
  fields:
    headers:
      names:
        User-Agent: keep
providers:
  docker:
    exposedByDefault: false
  file:
    directory: /etc/traefik/dynamic
    watch: true
http:
  routers:
    shop:
      rule: "Host(`shop.test`) || Host(`www.shop.test`)"
      entryPoints: [websecure]
      service: shop
      middlewares:
        - redirect
  services:
    shop:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:3000"
"#;
        let value = parse(text);
        assert_eq!(value["entryPoints"]["web"]["address"], ":80");
        assert_eq!(value["api"]["insecure"], true);
        assert_eq!(
            value["accessLog"]["filePath"],
            "/var/log/traefik/access.log"
        );
        assert_eq!(
            value["providers"]["file"]["directory"],
            "/etc/traefik/dynamic"
        );
        assert_eq!(
            value["http"]["routers"]["shop"]["rule"],
            "Host(`shop.test`) || Host(`www.shop.test`)"
        );
        assert_eq!(
            value["http"]["routers"]["shop"]["entryPoints"],
            json!(["websecure"])
        );
        assert_eq!(
            value["http"]["routers"]["shop"]["middlewares"],
            json!(["redirect"])
        );
        assert_eq!(
            value["http"]["services"]["shop"]["loadBalancer"]["servers"][0]["url"],
            "http://127.0.0.1:3000"
        );
    }

    #[test]
    fn rubbish_reads_as_little_as_possible() {
        assert_eq!(parse(""), Value::Null);
        assert_eq!(parse("just words")["x"], Value::Null);
        assert_eq!(parse("a: |\n  long\n  text\nb: 1")["b"], 1);
    }
}
