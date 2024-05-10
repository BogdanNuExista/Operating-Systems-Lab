#!/bin/bash

MALICIOUS_DIR_NAME="MaliciousFiles"

# Function to check for malicious words
check_malicious_words() {
    local file="$1"
    local malicious_words=("corrupted" "attack" "risk" "malicious" "malware" "virus")

    # Read the file line by line and check for malicious words
    while IFS= read -r line; do
        for word in "${malicious_words[@]}"; do
            if grep -q -i -w "$word" <<< "$line"; then
                echo "Malicious word found: $word"
                return 1 # Found malicious word
            fi
        done
    done < "$file"

    return 0 # No malicious word found
}

# Check file permissions and run checks if no permissions
check_permissions_and_run_checks() {
    local file="$1"

    if [ ! -r "$file" ] || [ ! -w "$file" ]; then
        echo "File $file has no read or write permissions. Running checks..."
        # Check number of lines

        chmod ugo+rw "$file"

        num_lines=$(wc -l < "$file")
        echo "Number of lines: $num_lines"

        # Check number of words
        num_words=$(wc -w < "$file")
        echo "Number of words: $num_words"

        # Check number of characters
        num_chars=$(wc -c < "$file")
        echo "Number of characters: $num_chars"

        # Check for malicious words
        if ! check_malicious_words "$file"; then
            echo "File $file contains malicious content."
            chmod ugo-rw "$file"
            # Move the file to the MaliciousFiles directory
            if ! mv "$file" "$MALICIOUS_DIR_NAME"; then
                echo "Failed to move file to $MALICIOUS_DIR_NAME directory."
                exit 1
             fi
        else
            echo "File $file is clean from malicious content."
        fi
    else
        echo "File $file has permissions. No need to run checks."
    fi

    # Remove write permissions after checks
    chmod ugo-rw "$file"
}

# Main script
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <file>"
    exit 1
fi

file="$1"

if [ ! -f "$file" ]; then
    echo "Error: File $file does not exist."
    exit 1
fi

check_permissions_and_run_checks "$file"
