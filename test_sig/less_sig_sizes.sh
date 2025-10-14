#!/bin/bash

# Array of algorithm variants to test
variants=(
    "LESS-252-192"
    "LESS-252-68"
    "LESS-252-45"
    "LESS-400-220"
    "LESS-400-102"
    "LESS-548-345"
    "LESS-548-137"
)

# --- Script Start ---

echo "-----------------------------------------"
echo "Retrieving Maximum Signature Sizes..."
echo "-----------------------------------------"

# Loop through each variant in the array
for variant in "${variants[@]}"
do
    # Run the test program, find the relevant line, and extract the 4th word (the size)
    max_sig_size=$(./test_sig "$variant" | grep "Maximum signature length" | awk '{print $4}')

    # Check if a size was successfully extracted
    if [ -n "$max_sig_size" ]; then
        # Print the result in a neatly formatted table using printf
        printf "%-15s -> %s bytes\n" "$variant" "$max_sig_size"
    else
        printf "%-15s -> Not found\n" "$variant"
    fi
done

echo "-----------------------------------------"
