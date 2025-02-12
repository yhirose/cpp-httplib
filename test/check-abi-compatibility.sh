#!/bin/bash
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 old_library.so new_library.so"
    exit 1
fi

OLD_LIB=$1
NEW_LIB=$2

OLD_FUNCS=_old_funcs.txt
NEW_FUNCS=_new_funcs.txt
OLD_VARS=_old_vars.txt
NEW_VARS=_new_vars.txt

# Extract function symbols from the old and new libraries
nm -C --defined-only $OLD_LIB | c++filt | awk '$2 ~ /[TWt]/ {print substr($0, index($0,$3))}' | sort > $OLD_FUNCS
nm -C --defined-only $NEW_LIB | c++filt | awk '$2 ~ /[TWt]/ {print substr($0, index($0,$3))}' | sort > $NEW_FUNCS

# Extract variable symbols from the old and new libraries
nm -C --defined-only $OLD_LIB | c++filt | awk '$2 ~ /[BDGVs]/ {print substr($0, index($0,$3))}' | sort > $OLD_VARS
nm -C --defined-only $NEW_LIB | c++filt | awk '$2 ~ /[BDGVs]/ {print substr($0, index($0,$3))}' | sort > $NEW_VARS

# Initialize error flag and message
error_flag=0
error_message=""

# Check for removed function symbols
removed_funcs=$(comm -23 $OLD_FUNCS $NEW_FUNCS)
if [ -n "$removed_funcs" ]; then
    error_flag=1
    error_message+="[Removed Functions]\n$removed_funcs\n\n"
fi

# Check for removed variable symbols
removed_vars=$(comm -23 $OLD_VARS $NEW_VARS)
if [ -n "$removed_vars" ]; then
    error_flag=1
    error_message+="[Removed Variables]\n$removed_vars\n\n"
fi

# Check for added variable symbols
added_vars=$(comm -13 $OLD_VARS $NEW_VARS)
if [ -n "$added_vars" ]; then
    error_flag=1
    error_message+="[Added Variables]\n$added_vars\n\n"
fi

# Remove temporary files
rm -f $NEW_FUNCS $OLD_FUNCS $OLD_VARS $NEW_VARS

# Display error messages if any
if [ "$error_flag" -eq 1 ]; then
    echo -en "$error_message"
    echo "ABI compatibility check failed."
    exit 1
fi

echo "ABI compatibility check passed: No variable symbols were removed or added, and no function symbols were removed."
exit 0
