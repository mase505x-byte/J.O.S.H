_OUTPUT"${OUTPUT_DIR}/raw_scan.xml"

mkdir -p "$OUTPUT_DIR"
echo "Scanning $TARGET..."

nmap -sV --script vuln --script-args mincvss7.0 "$TARGET" > "$RAW_OUTPUT" 2>&1

echo -e "${BLUE}================================================================${NC}"
echo "         Vulnerability Scan Results for $TARGET"
echo -e "${BLUE}================================================================${NC}"
echo "Scan started at: $(date)"
echo "Raw output: $RAW_OUTPUT"
echo ""

# Show open ports
echo -e "${YELLOW}Open Ports:${NC}"
grep -E "open|filtered" "$RAW_OUTPUT" | head -20

# Show vulnerabilities
echo -e "${YELLOW}Potential Vulnerabilities:${NC}"
grep -E "VULNERABLE|EXPOSED" "$RAW_OUTPUT" | head -20

echo ""
echo "Full report saved in $OUTPUT_DIR"
