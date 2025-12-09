#!/usr/bin/env python3
"""
Script to update the httplib.cppm module file based on changes to httplib.h.

This script:
1. Reads the existing exported symbols from modules/httplib.cppm
2. Analyses git diff to find added/removed declarations in httplib.h
3. Updates httplib.cppm by adding new exports and removing deleted ones
"""

import re
import subprocess
import sys
from pathlib import Path
from re import Match
from subprocess import CalledProcessError, CompletedProcess
from typing import Set, List, Tuple, Optional


def extract_exported_symbols(cppm_content: str) -> Set[str]:
    """
    Extract all symbols that are currently exported in the module file.
    
    @param cppm_content Content of the .cppm module file
    @return Set of symbol names that are already exported
    """
    exported: Set[str] = set()
    
    # Match patterns like: using httplib::SymbolName;
    pattern: str = r'using\s+httplib::(\w+);'
    matches: List[str] = re.findall(pattern, cppm_content)
    exported.update(matches)
    
    # Match patterns in nested namespace like: using httplib::stream::SymbolName;
    pattern: str = r'using\s+httplib::stream::(\w+);'
    matches: List[str] = re.findall(pattern, cppm_content)
    exported.update(matches)
    
    return exported


def extract_exported_symbols(cppm_content: str) -> Set[str]:
    """
    Extract all symbols that are currently exported in the module file.
    
    @param cppm_content Content of the .cppm module file
    @return Set of symbol names that are already exported
    """
    exported: Set[str] = set()
    
    pattern: str = r'using\s+httplib::(\w+);'
    matches: List[str] = re.findall(pattern, cppm_content)
    exported.update(matches)
    
    pattern: str = r'using\s+httplib::stream::(\w+);'
    matches: List[str] = re.findall(pattern, cppm_content)
    exported.update(matches)
    
    return exported


def get_git_diff(file_path: str, base_ref: str = "HEAD") -> Optional[str]:
    """
    Get the git diff for a specific file.
    
    @param file_path Path to the file to diff
    @param base_ref Git reference to compare against (default: HEAD)
    @return The git diff output, or None if error
    """
    try:
        result: CompletedProcess = subprocess.run(
            ["git", "diff", base_ref, "--", file_path],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except CalledProcessError as e:
        print(f"Error getting git diff: {e}", file=sys.stderr)
        return None


def is_in_detail_namespace(line: str) -> bool:
    """
    Check if a line appears to be in a detail namespace.
    
    @param line The line to check
    @return True if the line is likely in a detail namespace
    """
    return 'detail::' in line or line.strip().startswith('namespace detail')


def is_member_function_or_field(line: str, prev_context: List[str]) -> bool:
    """
    Heuristic to detect if a declaration is likely a member function or field.
    
    @param line The current line
    @param prev_context Previous few lines for context
    @return True if it looks like a member declaration
    """
    # Check if we're inside a class/struct by looking at previous context
    for prev_line in reversed(prev_context[-10:]):  # Look at last 10 lines
        stripped: str = prev_line.strip()
        # If we see a class/struct declaration recently without a closing brace, likely inside it
        if re.match(r'^(?:public|private|protected):', stripped):
            return True
        # Common member function patterns
        if stripped.startswith('~') or stripped.startswith('explicit '):
            return True
    
    stripped: str = line.strip()
    # Lines with multiple leading spaces are often inside class definitions
    if line.startswith('  ') and not line.startswith('   '):  # Exactly 2 spaces
        return True
    
    return False


def extract_declarations_from_diff(diff_content: str) -> Tuple[Set[str], Set[str]]:
    """
    Extract added and removed declarations from a git diff.
    
    @param diff_content The git diff output
    @return Tuple of (added_symbols, removed_symbols)
    """
    added_symbols: Set[str] = set()
    removed_symbols: Set[str] = set()
    
    lines: List[str] = diff_content.split('\n')
    context_lines: List[str] = []
    
    for line in lines:
        if not line.startswith('@@'):
            context_lines.append(line)
            if len(context_lines) > 20:
                context_lines.pop(0)
        
        if is_in_detail_namespace(line):
            continue
        
        if is_member_function_or_field(line, context_lines):
            continue
        
        if line.startswith('+') and not line.startswith('+++'):
            content: str = line[1:].strip()
            
            enum_match: Optional[Match[str]] = re.match(r'^enum\s+(?:class\s+)?(\w+)', content)
            if enum_match:
                added_symbols.add(enum_match.group(1))
            
            class_match: Optional[Match[str]] = re.match(r'^(?:struct|class)\s+(\w+)(?:\s+final)?(?:\s*:\s*public)?', content)
            if class_match and not content.endswith(';'):
                added_symbols.add(class_match.group(1))
            
            using_match: Optional[Match[str]] = re.match(r'^using\s+(\w+)\s+=', content)
            if using_match:
                added_symbols.add(using_match.group(1))
            
            func_match: Optional[Match[str]] = re.match(r'^(?:inline\s+)?(?:const\s+)?(?:std::)?[\w:]+\s+(\w+)\s*\([^)]*\)\s*(?:const)?;', content)
            if func_match and not '->' in content:
                symbol: str = func_match.group(1)
                if symbol not in {'operator', 'if', 'for', 'while', 'return', 'const', 'static'}:
                    if not (symbol.endswith('_internal') or symbol.endswith('_impl') or symbol.endswith('_core')):
                        added_symbols.add(symbol)
        
        elif line.startswith('-') and not line.startswith('---'):
            content: str = line[1:].strip()
            
            enum_match: Optional[Match[str]] = re.match(r'^enum\s+(?:class\s+)?(\w+)', content)
            if enum_match:
                removed_symbols.add(enum_match.group(1))
            
            class_match: Optional[Match[str]] = re.match(r'^(?:struct|class)\s+(\w+)(?:\s+final)?(?:\s*:\s*public)?', content)
            if class_match and not content.endswith(';'):
                removed_symbols.add(class_match.group(1))
            
            using_match: Optional[Match[str]] = re.match(r'^using\s+(\w+)\s+=', content)
            if using_match:
                removed_symbols.add(using_match.group(1))
            
            func_match: Optional[Match[str]] = re.match(r'^(?:inline\s+)?(?:const\s+)?(?:std::)?[\w:]+\s+(\w+)\s*\([^)]*\)\s*(?:const)?;', content)
            if func_match and not '->' in content:
                symbol: str = func_match.group(1)
                if symbol not in {'operator', 'if', 'for', 'while', 'return', 'const', 'static'}:
                    if not (symbol.endswith('_internal') or symbol.endswith('_impl') or symbol.endswith('_core')):
                        removed_symbols.add(symbol)
    
    return added_symbols, removed_symbols


def update_module_exports(cppm_path: Path, symbols_to_add: Set[str], symbols_to_remove: Set[str]) -> bool:
    """
    Update the module file by adding and removing symbols.
    
    @param cppm_path Path to the .cppm file
    @param symbols_to_add Symbols to add to exports
    @param symbols_to_remove Symbols to remove from exports
    @return True if file was modified
    """
    content: str = cppm_path.read_text()
    original_content: str = content
    
    for symbol in symbols_to_remove:
        pattern: str = rf'^\s*using httplib::{re.escape(symbol)};$'
        content: str = re.sub(pattern, '', content, flags=re.MULTILINE)
        
        pattern: str = rf'^\s*using httplib::stream::{re.escape(symbol)};$'
        content: str = re.sub(pattern, '', content, flags=re.MULTILINE)
    
    if symbols_to_add:
        pattern: str = r'(.*using httplib::\w+;)'
        matches: List[Match[str]] = list(re.finditer(pattern, content, re.MULTILINE))
        
        if matches:
            last_match: Match[str] = matches[-1]
            insert_pos: int = last_match.end()
            
            new_exports: str = '\n'.join(f"    using httplib::{symbol};" for symbol in sorted(symbols_to_add))
            content: str = content[:insert_pos] + '\n' + new_exports + content[insert_pos:]
    
    content: str = re.sub(r'\n\n\n+', '\n\n', content)
    
    if content != original_content:
        cppm_path.write_text(content)
        return True
    
    return False


def main() -> None:
    """Main entry point for the script."""
    script_dir: Path = Path(__file__).parent
    header_path: Path = script_dir / "httplib.h"
    cppm_path: Path = script_dir / "modules" / "httplib.cppm"
    
    if not header_path.exists():
        print(f"Error: {header_path} not found")
        sys.exit(1)
    
    if not cppm_path.exists():
        print(f"Error: {cppm_path} not found")
        sys.exit(1)
    
    print("Analyzing git diff for httplib.h...")
    diff_content: Optional[str] = get_git_diff(str(header_path))
    
    if diff_content is None:
        print("Error: Could not get git diff")
        sys.exit(1)
    
    if not diff_content.strip():
        print("No changes detected in httplib.h")
        sys.exit(0)
    
    print("Extracting declarations from diff...")
    added_symbols, removed_symbols = extract_declarations_from_diff(diff_content)
    
    if not added_symbols and not removed_symbols:
        print("No declaration changes detected")
        sys.exit(0)
    
    print(f"\nFound {len(added_symbols)} added declarations:")
    for symbol in sorted(added_symbols):
        print(f"  + {symbol}")
    
    print(f"\nFound {len(removed_symbols)} removed declarations:")
    for symbol in sorted(removed_symbols):
        print(f"  - {symbol}")
    
    print("\nReading current module exports...")
    cppm_content: str = cppm_path.read_text()
    current_exports: Set[str] = extract_exported_symbols(cppm_content)
    
    symbols_to_add: Set[str] = added_symbols - current_exports
    symbols_to_remove: Set[str] = removed_symbols & current_exports
    
    if not symbols_to_add and not symbols_to_remove:
        print("\nModule file is already up to date")
        sys.exit(0)
    
    print(f"\nUpdating module file:")
    if symbols_to_add:
        print(f"  Adding {len(symbols_to_add)} symbols")
    if symbols_to_remove:
        print(f"  Removing {len(symbols_to_remove)} symbols")
    
    modified: bool = update_module_exports(cppm_path, symbols_to_add, symbols_to_remove)
    
    if modified:
        print(f"\n✓ Successfully updated {cppm_path}")
    else:
        print(f"\n✓ No changes needed to {cppm_path}")


if __name__ == "__main__":
    main()
