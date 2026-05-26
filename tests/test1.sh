# Resolve the directory where the script is located, regardless of execution path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

# 1. Go to <dir_where_the_script_is>/test1
cd "$SCRIPT_DIR/test1" || { echo "Error: Could not enter directory $SCRIPT_DIR/test1"; exit 1; }

# 2. Run the program
../../program

# 3. Check for the "pldest" directory and its layout
PLDEST="pldest"

# Check if the main pldest directory exists
if [[ ! -d "$PLDEST" ]]; then
    echo "Validation failed: Directory '$PLDEST' does not exist."
    exit 1
fi

# Array of expected subdirectories
EXPECTED_DIRS=("d1" "d2" "d3" "d4")

for dir in "${EXPECTED_DIRS[@]}"; do
    # Check if subdirectory exists
    if [[ ! -d "$PLDEST/$dir" ]]; then
        echo "Validation failed: Directory '$PLDEST/$dir' is missing."
        exit 1
    fi
    
    # Check if the helloworld.txt file exists inside the subdirectory
    if [[ ! -f "$PLDEST/$dir/helloworld.txt" ]]; then
        echo "Validation failed: File '$PLDEST/$dir/helloworld.txt' is missing."
        exit 1
    fi
done

# Strict Mode: Verify there are exactly 4 directories and 4 files to match the screenshot perfectly
# (This ensures the program didn't create unexpected extra files like 'd5' or 'error.log')
ACTUAL_DIR_COUNT=$(find "$PLDEST" -mindepth 1 -maxdepth 1 -type d | wc -l)
ACTUAL_FILE_COUNT=$(find "$PLDEST" -type f | wc -l)

if [[ "$ACTUAL_DIR_COUNT" -ne 4 ]]; then
    echo "Validation failed: Expected exactly 4 subdirectories in $PLDEST, but found $ACTUAL_DIR_COUNT."
    exit 1
fi

if [[ "$ACTUAL_FILE_COUNT" -ne 4 ]]; then
    echo "Validation failed: Expected exactly 4 files in $PLDEST, but found $ACTUAL_FILE_COUNT."
    exit 1
fi

# If it makes it here, everything is perfect.
echo "Success: Directory layout perfectly matches the expected structure."
exit 0
