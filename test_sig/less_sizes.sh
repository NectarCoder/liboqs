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
echo "Retrieving Key Sizes..."
echo "-----------------------------------------"

# Loop through each variant in the array
for variant in "${variants[@]}"
do
    # Run the test program and extract the key sizes
    pub_size=$(./test_sig "$variant" | grep "Public key length" | awk '{print $4}')
    sec_size=$(./test_sig "$variant" | grep "Secret key length" | awk '{print $4}')

    # Check if sizes were successfully extracted
    if [ -n "$pub_size" ] && [ -n "$sec_size" ]; then
        # Print the result in a neatly formatted table using printf
        printf "%-15s -> Public: %s bytes, Secret: %s bytes\n" "$variant" "$pub_size" "$sec_size"
    else
        printf "%-15s -> Not found\n" "$variant"
    fi
done

echo "-----------------------------------------"
