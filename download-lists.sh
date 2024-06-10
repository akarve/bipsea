#!/bin/sh
set -e

GITHUB_39="https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039"
FILES_39="chinese_simplified.txt chinese_traditional.txt czech.txt english.txt french.txt italian.txt japanese.txt korean.txt portuguese.txt spanish.txt"


for file in $FILES_39; do
    curl -s "$GITHUB_39/$file" -o "src/bipsea/wordlists/$file"
done
