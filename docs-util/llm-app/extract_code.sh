# Extract code block from a <details> section identified by data-file attribute.
# Usage: extract_code <file> <data-file>
# Example: extract_code ch01.md "main.cpp"
extract_code() {
  local file="$1" name="$2"
  local output
  output=$(awk -v name="$name" '
    $0 ~ "data-file=\"" name "\"" { found=1; next }
    found && /^```/ && !inside { inside=1; next }
    inside && /^```/ { exit }
    inside { print }
  ' "$file")
  if [ -z "$output" ]; then
    echo "ERROR: extract_code: no match for data-file=\"$name\" in $file" >&2
    return 1
  fi
  printf '%s\n' "$output"
}
