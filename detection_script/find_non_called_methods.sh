#!/bin/bash
set -e

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}

check_system_memory() {
    local available_mem_kb=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    local available_mem_gb=$((available_mem_kb / 1024 / 1024))
    echo $available_mem_gb
}

count_source_files() {
    local dir="$1"
    find "$dir" -type f \( -name "*.c" -o -name "*.cpp" -o -name "*.h" -o -name "*.hpp" \) | wc -l
}

check_directory_size() {
    local dir="$1"
    local file_count=$(count_source_files "$dir")
    local dir_size_mb=$(du -sm "$dir" 2>/dev/null | cut -f1)
    
    log_message "Directory analysis: $file_count source files, ${dir_size_mb}MB total size"
    
    if [ "$file_count" -gt 1000 ] || [ "$dir_size_mb" -gt 500 ]; then
        log_message "WARNING: Large codebase detected (${file_count} files, ${dir_size_mb}MB)"
        log_message "Consider analyzing a smaller subset for better performance"
        return 1
    fi
    return 0
}

if [ $# -lt 2 ]; then
    echo "Usage: $0 <project_path> <project_name> [output_file] [--max-heap 16g] [--initial-heap 4g]"
    echo "Example: $0 /path/to/project MyProject output.json"
    exit 1
fi

PROJECT_PATH="$1"
PROJECT_NAME="$2"
OUTPUT_FILE="${3:-non_called_methods.json}"

if [ ! -d "$PROJECT_PATH" ]; then
    log_message "ERROR: Project path does not exist: $PROJECT_PATH"
    exit 1
fi

available_mem=$(check_system_memory)
log_message "Available system memory: ${available_mem}GB"

if [ "$available_mem" -lt 8 ]; then
    log_message "WARNING: Low system memory (${available_mem}GB), using conservative settings"
    DEFAULT_MAX_HEAP="4g"
    DEFAULT_INITIAL_HEAP="2g"
elif [ "$available_mem" -lt 16 ]; then
    DEFAULT_MAX_HEAP="8g"
    DEFAULT_INITIAL_HEAP="4g"
else
    DEFAULT_MAX_HEAP="16g"  
    DEFAULT_INITIAL_HEAP="8g"
fi

MAX_HEAP="$DEFAULT_MAX_HEAP"
INITIAL_HEAP="$DEFAULT_INITIAL_HEAP"

shift 2  
if [[ "$1" != "--"* ]]; then
    OUTPUT_FILE="$1"
    shift
fi

# Process memory parameters
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --max-heap)
            MAX_HEAP="$2"
            shift 2
            ;;
        --initial-heap)
            INITIAL_HEAP="$2"
            shift 2
            ;;
        *)
            # Ignore unknown arguments
            shift
            ;;
    esac
done

log_message "Memory settings: Max heap: $MAX_HEAP, Initial heap: $INITIAL_HEAP"

if ! check_directory_size "$PROJECT_PATH"; then
    log_message "WARNING: Large codebase may cause memory issues. Consider using a smaller subset."
fi

if ! command -v joern &> /dev/null; then
    log_message "ERROR: Joern is not installed or not in PATH."
    log_message "Please install Joern first: https://github.com/joernio/joern"
    
    cat > "$OUTPUT_FILE" << EOF
{
  "status": "error",
  "error": "Joern not available",
  "unused_functions": [],
  "total_functions": 0,
  "unused_count": 0,
  "analysis_summary": {
    "project_name": "$PROJECT_NAME",
    "project_path": "$PROJECT_PATH",
    "status": "failed",
    "reason": "Joern not installed"
  }
}
EOF
    exit 1
fi

log_message "Starting analysis for project: $PROJECT_NAME"
log_message "Project path: $PROJECT_PATH"
log_message "Output file: $OUTPUT_FILE"

# Create temporary Joern script
TEMP_SCRIPT=$(mktemp /tmp/joern_script.XXXXXX.sc)

cat > "$TEMP_SCRIPT" << 'EOF'
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language._
import better.files._
import ujson._

// Get all methods (filtering out external and system methods)
val allMethods = cpg.method
  .filterNot(_.isExternal)
  .filterNot(m => m.name.startsWith("<") || 
             m.name.startsWith("__") || 
             m.name == "main" || 
             m.name.startsWith("operator") || 
             m.name.startsWith("~"))
  .l

// Get called methods (methods that have incoming calls)
val calledMethods = cpg.method
  .filterNot(_.isExternal)
  .filterNot(m => m.name.startsWith("<") || 
             m.name.startsWith("__") || 
             m.name == "main" || 
             m.name.startsWith("operator") || 
             m.name.startsWith("~"))
  .filter(_.start.callIn.nonEmpty)
  .l

// Find non-called methods with their file information
val nonCalledMethods = allMethods.diff(calledMethods).map { method =>
  val filename = method.file.name.l.headOption.getOrElse("unknown")
  val line = method.lineNumber.getOrElse(-1)
  Obj(
    "type" -> "unused_method",
    "name" -> method.name,
    "file" -> filename,
    "line" -> line
  )
}.sortBy(_.obj("name").str)

// Create JSON structure as an array (expected by correlation agent)
val jsonData = Arr(nonCalledMethods: _*)

// Write to file
val outputFile = File(OUTPUT_FILE)
outputFile.overwrite(ujson.write(jsonData, indent = 2))

println(s"Analysis complete! Results saved to: $OUTPUT_FILE")

// Print JSON to console
println("\nJSON Output:")
println(ujson.write(jsonData, indent = 2))
EOF

# Add project variables to the Scala script
sed -i "1i val PROJECT_NAME = \"$PROJECT_NAME\"" "$TEMP_SCRIPT"
sed -i "2i val OUTPUT_FILE = \"$OUTPUT_FILE\"" "$TEMP_SCRIPT"

# Configure Joern-specific JVM memory options
log_message "Memory configuration: Initial=$INITIAL_HEAP, Max=$MAX_HEAP"

# Function to create fallback results on failure
create_fallback_results() {
    local reason="$1"
    log_message "Creating fallback results due to: $reason"
    
    cat > "$OUTPUT_FILE" << EOF
{
  "status": "completed_with_fallback",
  "error": "$reason",
  "unused_functions": [],
  "total_functions": 0,
  "unused_count": 0,
  "analysis_summary": {
    "project_name": "$PROJECT_NAME",
    "project_path": "$PROJECT_PATH",
    "status": "fallback",
    "reason": "$reason"
  }
}
EOF
    log_message "Fallback results created: $OUTPUT_FILE"
}

# First, try to parse the project to create CPG
log_message "Creating CPG for the project..."
CPG_FILE="/tmp/${PROJECT_NAME}.cpg"

# Try CPG creation with timeout and memory limits
log_message "Attempting CPG creation with timeout (15 minutes) and memory limits..."

# Run joern-parse and capture exit code properly
joern-parse "$PROJECT_PATH" -o "$CPG_FILE" \
    -J-Xms$INITIAL_HEAP -J-Xmx$MAX_HEAP \
    -J-XX:+UseG1GC -J-XX:+UseStringDeduplication \
    -J-XX:MaxGCPauseMillis=200 2>&1 | grep -v "ReachingDefPass.*Skipping" || true

CPG_EXIT_CODE=$?

if [ $CPG_EXIT_CODE -ne 0 ]; then
    if [ $CPG_EXIT_CODE -eq 124 ]; then
        create_fallback_results "CPG creation timed out after 15 minutes (codebase too large)"
    elif [ $CPG_EXIT_CODE -eq 137 ]; then
        create_fallback_results "CPG creation killed (out of memory)"
    elif [ $CPG_EXIT_CODE -eq 130 ]; then
        create_fallback_results "CPG creation interrupted (SIGINT)"
    else
        create_fallback_results "CPG creation failed (exit code: $CPG_EXIT_CODE)"
    fi
    
    rm -f "$TEMP_SCRIPT" "$CPG_FILE"
    exit 0
fi

if [ ! -f "$CPG_FILE" ]; then
    create_fallback_results "CPG file not created"
    rm -f "$TEMP_SCRIPT"
    exit 0
fi

log_message "CPG created successfully, running analysis..."

# Run Joern analysis with timeout and better error handling
log_message "Running Joern analysis..."

# Run joern command and capture exit code properly
timeout 1800 joern \
    -J-Xms$INITIAL_HEAP -J-Xmx$MAX_HEAP \
    -J-XX:+UseG1GC -J-XX:+UseStringDeduplication \
    -J-XX:MaxGCPauseMillis=200 \
    --script "$TEMP_SCRIPT" --params "$CPG_FILE" 2>&1 || true

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    if [ $EXIT_CODE -eq 124 ]; then
        create_fallback_results "Analysis timed out after 30 minutes"
    elif [ $EXIT_CODE -eq 137 ]; then
        create_fallback_results "Analysis killed (out of memory)"
    else
        create_fallback_results "Analysis failed (exit code: $EXIT_CODE)"
    fi
    
    rm -f "$TEMP_SCRIPT" "$CPG_FILE"
    exit 0
fi

# Verify output file was created successfully
if [ -f "$OUTPUT_FILE" ]; then
    log_message "Analysis completed successfully"
    
    # Validate JSON if possible
    if command -v python3 &> /dev/null; then
        if ! python3 -c "import json; json.load(open('$OUTPUT_FILE'))" 2>/dev/null; then
            log_message "Output file is not valid JSON, creating fallback"
            create_fallback_results "Invalid JSON output"
        fi
    fi
    
    # Display statistics
    if command -v grep &> /dev/null && command -v wc &> /dev/null; then
        METHOD_COUNT=$(grep -c "unused_method" "$OUTPUT_FILE" 2>/dev/null || echo "0")
        log_message "Analysis completed! $METHOD_COUNT unused methods detected."
    else
        log_message "Analysis completed!"
    fi
    log_message "Results saved to: $OUTPUT_FILE"
else
    create_fallback_results "No output file generated"
fi

# Clean up temporary files
log_message "Cleaning up temporary files..."
rm -f "$TEMP_SCRIPT" "$CPG_FILE"
