// pattern: Functional Core

//! Windows service command-line parsing that is testable on every host.

use anyhow::{Result, bail};

/// Extract the executable (`argv[0]`) from a Windows service command line.
///
/// This follows the quoting rules used by `CommandLineToArgvW` for the first argument. The returned
/// value excludes surrounding quotes and never includes later service arguments.
///
/// # Errors
/// Returns an error when the command line has no executable argument or contains an unterminated
/// quoted executable path.
pub fn executable_from_command_line(command_line: &str) -> Result<String> {
    let mut chars = command_line.chars().peekable();
    while matches!(chars.peek(), Some(character) if character.is_whitespace()) {
        chars.next();
    }
    let Some(first) = chars.peek().copied() else {
        bail!("service command line has no executable path")
    };
    if first == '"' {
        chars.next();
        let mut executable = String::new();
        let mut backslashes = 0usize;
        for character in chars.by_ref() {
            match character {
                '\\' => backslashes += 1,
                '"' => {
                    if backslashes % 2 == 0 {
                        executable.extend(std::iter::repeat_n('\\', backslashes / 2));
                        return if executable.is_empty() {
                            Err(anyhow::anyhow!(
                                "service command line has no executable path"
                            ))
                        } else {
                            Ok(executable)
                        };
                    }
                    executable.extend(std::iter::repeat_n('\\', backslashes / 2));
                    executable.push('"');
                    backslashes = 0;
                }
                _ => {
                    executable.extend(std::iter::repeat_n('\\', backslashes));
                    backslashes = 0;
                    executable.push(character);
                }
            }
        }
        bail!("service command line has an unterminated executable quote")
    }

    let mut executable = String::new();
    while let Some(character) = chars.peek().copied() {
        if character.is_whitespace() {
            break;
        }
        executable.push(character);
        chars.next();
    }
    if executable.is_empty() {
        bail!("service command line has no executable path")
    }
    Ok(executable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_quoted_path_before_arguments() -> Result<()> {
        assert_eq!(
            executable_from_command_line(
                r#"  "C:\Program Files\SnipeSpotter\spotter-svc.exe" --service-name custom"#
            )?,
            r#"C:\Program Files\SnipeSpotter\spotter-svc.exe"#
        );
        Ok(())
    }

    #[test]
    fn extracts_unquoted_path_before_arguments() -> Result<()> {
        assert_eq!(
            executable_from_command_line(r"C:\SnipeSpotter\spotter-svc.exe --service-name custom")?,
            r"C:\SnipeSpotter\spotter-svc.exe"
        );
        Ok(())
    }

    #[test]
    fn preserves_escaped_quote_in_executable() -> Result<()> {
        assert_eq!(
            executable_from_command_line(r#""C:\x\\\"quoted.exe" --arg"#)?,
            r##"C:\x\"quoted.exe"##
        );
        Ok(())
    }

    #[test]
    fn rejects_empty_and_unterminated_commands() {
        assert!(executable_from_command_line(" \t").is_err());
        assert!(executable_from_command_line(r#""C:\missing.exe"#).is_err());
    }
}
