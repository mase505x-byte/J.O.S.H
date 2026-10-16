(global $TOK_EOF            i32(i32.const 0))
(global $TOK_TEXT           i32 (i32.const 1))
(global $TOK_NEWLINE        i32 (i32.const 2))
(global $TOK_STORE          i32 (i32.const 3))
(global $TOK_RETRIEVE       i32 (i32.const 4))
(global $TOK_EXECUTE        i32 (i32.const 5))
(global $TOK_IMM_STORE      i32 (i32.const 6))
(global $TOK_IMM_STORE      i32 (i32.const 7))
  (global $TOK_IMM_EXEC     i32 (i32.const 8))
  (global $TOK_DEFER        i32 (i32.const 9))
  (global $TOK_PLACEHOLDER  i32 (i32.const 10))
  (global $TOK_TERMINATOR   i32 (i32.const 11))

  ;; Scanner state lives in the VM state header: $VS_scan_ptr, $VS_scan_end,
  ;; $VS_scan_line.

  ;; scan_init(ptr, len): initialize scanner over a byte buffer
  (func $scan_init (export "scan_init") (param $ptr i32) (param $len i32)
    (i32.store (global.get $VS_scan_ptr) (local.get $ptr))
    (i32.store (global.get $VS_scan_end) (i32.add (local.get $ptr) (local.get $len)))
    (i32.store (global.get $VS_scan_line) (i32.const 1))
  )

  ;; scan_pos() -> i32: current scanner position
  (func $scan_pos (export "scan_pos") (result i32)
    (i32.load (global.get $VS_scan_ptr))
  )

  ;; scan_line() -> i32: current line number
  (func $scan_line_num (export "scan_line") (result i32)
    (i32.load (global.get $VS_scan_line))
  )

  ;; match_operator(b1, b2) -> token_type (0 if not an operator)
  ;; Given bytes 2 and 3 of a 3-byte UTF-8 sequence starting with E2,
  ;; return the token type or 0 if not a losp operator.
  (func $match_operator (param $b1 i32) (param $b2 i32) (result i32)
    ;; Most operators have b1 = 0x96
    (if (i32.eq (local.get $b1) (i32.const 0x96))
      (then
        ;; b2 distinguishes them
        (if (i32.eq (local.get $b2) (i32.const 0xBC)) (then (return (global.get $TOK_STORE))))        ;; ▼
        (if (i32.eq (local.get $b2) (i32.const 0xB2)) (then (return (global.get $TOK_RETRIEVE))))     ;; ▲
        (if (i32.eq (local.get $b2) (i32.const 0xB6)) (then (return (global.get $TOK_EXECUTE))))      ;; ▶
        (if (i32.eq (local.get $b2) (i32.const 0xBD)) (then (return (global.get $TOK_IMM_STORE))))    ;; ▽
        (if (i32.eq (local.get $b2) (i32.const 0xB3)) (then (return (global.get $TOK_IMM_RETR))))     ;; △
        (if (i32.eq (local.get $b2) (i32.const 0xB7)) (then (return (global.get $TOK_IMM_EXEC))))     ;; ▷
        (if (i32.eq (local.get $b2) (i32.const 0xA1)) (then (return (global.get $TOK_PLACEHOLDER))))  ;; □
      )
    )
    ;; Two operators have b1 = 0x97
    (if (i32.eq (local.get $b1) (i32.const 0x97))
      (then
        (if (i32.eq (local.get $b2) (i32.const 0xAF)) (then (return (global.get $TOK_DEFER))))        ;; ◯
        (if (i32.eq (local.get $b2) (i32.const 0x86)) (then (return (global.get $TOK_TERMINATOR))))   ;; ◆
      )
    )
    (i32.const 0)
  )

  ;; is_operator_at(ptr) -> token_type (0 if not an operator)
  ;; Check if the 3 bytes at ptr form a losp operator.
  ;; Caller must ensure ptr+2 < scan_end.
  (func $is_operator_at (export "is_operator_at")
    (param $ptr i32) (result i32)
    (if (i32.ne (i32.load8_u (local.get $ptr)) (i32.const 0xE2))
      (then (return (i32.const 0)))
    )
    (call $match_operator
      (i32.load8_u (i32.add (local.get $ptr) (i32.const 1)))
      (i32.load8_u (i32.add (local.get $ptr) (i32.const 2))))
  )

  ;; seg_reads_namespace(ptr, len) -> 1 when compiling the region would read
  ;; the namespace.
  ;;
  ;; Everything the compiler resolves at parse is an immediate operator: ▽ △ ▷
  ;; are the only three sites in SECTION 17a that call dict_get, and the
  ;; dynamic-name forms that also resolve at parse are reached only through
  ;; them (▼▲name and ▲▲name resolve in the frame, at run time). ◯ fires
  ;; nothing itself, but it carries text to be parsed later and is cheaper to
  ;; refuse than to reason about.
  ;;
  ;; So a region holding none of the four compiles against no namespace at all,
  ;; and may share a program with whatever was compiled before it. This is a
  ;; conservative test in one direction only: it may refuse a region that would
  ;; have been safe (a ▽ inside a ◯, say), never accept one that is not.
  ;;
  ;; It asks is_operator_at rather than matching bytes of its own — one reader
  ;; of what an operator looks like, the same rule the walker follows.
  ;; It runs over every body the batch considers, so it reads eight bytes at a
  ;; time and only falls to a byte at a time inside a word that holds a lead
  ;; byte. A body a thousand bytes long is common and this decides nothing
  ;; about it in nine cases out of ten.
  (func $seg_reads_namespace (param $ptr i32) (param $len i32) (result i32)
    (local $end i32)
    (local $word_end i32)
    (local $x i64)
    (local $tok i32)
    (if (i32.lt_u (local.get $len) (i32.const 3))
      (then (return (i32.const 0)))
    )
    ;; The last position an operator can start at is len-3.
    (local.set $end (i32.sub (i32.add (local.get $ptr) (local.get $len))
      (i32.const 2)))
    ;; A word load may read up to seven bytes past the position it tests, and
    ;; the two bytes past `end` are inside the region, so it stops eight short.
    (local.set $word_end (i32.sub (local.get $end) (i32.const 8)))
    (block $done
      (loop $scan
        (br_if $done (i32.ge_u (local.get $ptr) (local.get $end)))

        ;; Is 0xE2 anywhere in the next eight bytes? x ^ 0xE2… makes a lead
        ;; byte zero, and (y - 0x01…) & ~y & 0x80… is the usual test for a zero
        ;; byte in a word. No match skips all eight.
        (if (i32.lt_u (local.get $ptr) (local.get $word_end))
          (then
            (local.set $x
              (i64.xor (i64.load (local.get $ptr))
                (i64.const 0xE2E2E2E2E2E2E2E2)))
            (if (i64.eqz
                  (i64.and
                    (i64.and
                      (i64.sub (local.get $x) (i64.const 0x0101010101010101))
                      (i64.xor (local.get $x) (i64.const -1)))
                    (i64.const 0x8080808080808080)))
              (then
                (local.set $ptr (i32.add (local.get $ptr) (i32.const 8)))
                (br $scan)
              )
            )
          )
        )

        (if (i32.eq (i32.load8_u (local.get $ptr)) (i32.const 0xE2))
          (then
            (local.set $tok (call $is_operator_at (local.get $ptr)))
            (if (i32.or
                  (i32.or
                    (i32.eq (local.get $tok) (global.get $TOK_IMM_STORE))
                    (i32.eq (local.get $tok) (global.get $TOK_IMM_RETR)))
                  (i32.or
                    (i32.eq (local.get $tok) (global.get $TOK_IMM_EXEC))
                    (i32.eq (local.get $tok) (global.get $TOK_DEFER))))
              (then (return (i32.const 1)))
            )
          )
        )
        (local.set $ptr (i32.add (local.get $ptr) (i32.const 1)))
        (br $scan)
      )
    )
    (i32.const 0)
  )

  ;; seg_batch_full(program) -> 1 when the program has taken as many constants
  ;; as one batch may hold.
  ;;
  ;; Batching removes the cut, and with it the rule that a file of definitions
  ;; is bounded by the namespace rather than by the 65,535-constant ceiling on
  ;; one program. The cap puts that rule back: a run of definitions is cut when
  ;; the pool reaches it, so a source of any size still loads, in batches. It
  ;; is set well below the ceiling because a single construct may add several
  ;; constants after the check.
  (func $seg_batch_full (param $program i32) (param $need i32) (result i32)
    ;; No room for what this construct is about to add. A program that outgrows
    ;; its first page is reallocated and copied whole, and an unbatched stream
    ;; never pays that — so the batch ends rather than grow the extent.
    (if (i32.gt_u
          (i32.add (i32.load (i32.add (local.get $program) (i32.const 12)))
            (i32.add (local.get $need) (global.get $SEG_BATCH_HEADROOM)))
          (i32.sub (global.get $PAGE_SIZE) (global.get $PAYLOAD_OFFSET)))
      (then (return (i32.const 1)))
    )
    (i32.ge_u
      (i32.load
        (i32.add
          (i32.add (i32.load (local.get $program))
            (global.get $PAYLOAD_OFFSET))
          (global.get $PROGRAM_NCONST_OFF)))
      (global.get $SEG_BATCH_MAX_CONSTS))
  )

  ;; scan_skip_whitespace(): advance past spaces and tabs (NOT newlines)
  ;; scan_skip_blanks(): pass over spaces, tabs and newlines together.
  ;;
  ;; A □name declaration owns the blank run that follows it. The declaration is
  ;; part of an expression's source and stands in its text, so the run between
  ;; it and the first thing the body actually says is spacing within the
  ;; declaration list rather than a separator the body owes output for. Line
  ;; numbers are kept, because they are what an error report names.
  (func $scan_skip_blanks
    (local $b i32)
    (block $done
      (loop $loop
        (br_if $done
          (i32.ge_u (i32.load (global.get $VS_scan_ptr))
            (i32.load (global.get $VS_scan_end))))
        (local.set $b (i32.load8_u (i32.load (global.get $VS_scan_ptr))))
        (br_if $done
          (i32.and
            (i32.and
              (i32.ne (local.get $b) (i32.const 0x20))
              (i32.ne (local.get $b) (i32.const 0x09)))
            (i32.and
              (i32.ne (local.get $b) (i32.const 0x0A))
              (i32.ne (local.get $b) (i32.const 0x0D)))))
        (if (i32.eq (local.get $b) (i32.const 0x0A))
          (then
            (i32.store (global.get $VS_scan_line)
              (i32.add (i32.load (global.get $VS_scan_line)) (i32.const 1))))
        )
        (i32.store (global.get $VS_scan_ptr)
          (i32.add (i32.load (global.get $VS_scan_ptr)) (i32.const 1)))
        (br $loop)
      )
    )
  )

  (func $scan_skip_whitespace (export "scan_skip_whitespace")
    (local $b i32)
    (block $done
      (loop $loop
        (br_if $done (i32.ge_u (i32.load (global.get $VS_scan_ptr)) (i32.load (global.get $VS_scan_end))))
        (local.set $b (i32.load8_u (i32.load (global.get $VS_scan_ptr))))
        (br_if $done
          (i32.and
            (i32.ne (local.get $b) (i32.const 0x20))   ;; space
            (i32.ne (local.get $b) (i32.const 0x09))))  ;; tab
        (i32.store (global.get $VS_scan_ptr)
          (i32.add (i32.load (global.get $VS_scan_ptr)) (i32.const 1)))
        (br $loop)
      )
    )
  )

  ;; scan_peek_rune() -> i64 (packed: hi=codepoint, lo=byte_length)
  ;; Returns the next codepoint without advancing. Returns 0 at EOF.
  (func $scan_peek_rune (export "scan_peek_rune") (result i64)
    (if (i32.ge_u (i32.load (global.get $VS_scan_ptr)) (i32.load (global.get $VS_scan_end)))
      (then (return (i64.const 0)))
    )
    (call $utf8_next (i32.load (global.get $VS_scan_ptr)) (i32.load (global.get $VS_scan_end)))
  )

  ;; is_ident_byte(b) -> i32 (1 if letter/digit/underscore, 0 otherwise)
  ;; Identifiers are ASCII letters, digits, and underscores.
  ;; Multi-byte UTF-8 chars are NOT identifier chars.
  (func $is_ident_byte (param $b i32) (result i32)
    ;; underscore
    (if (i32.eq (local.get $b) (i32.const 0x5F)) (then (return (i32.const 1))))
    ;; 0-9
    (if (i32.and
          (i32.ge_u (local.get $b) (i32.const 0x30))
          (i32.le_u (local.get $b) (i32.const 0x39)))
      (then (return (i32.const 1))))
    ;; A-Z
    (if (i32.and
          (i32.ge_u (local.get $b) (i32.const 0x41))
          (i32.le_u (local.get $b) (i32.const 0x5A)))
      (then (return (i32.const 1))))
    ;; a-z
    (if (i32.and
          (i32.ge_u (local.get $b) (i32.const 0x61))
          (i32.le_u (local.get $b) (i32.const 0x7A)))
      (then (return (i32.const 1))))
    (i32.const 0)
  )

  ;; scan_name() -> i64 (packed: hi=ptr, lo=len)
  ;; Read an identifier name starting at scan_ptr.
  ;; Identifiers consist of letters, digits, and underscores.
  ;; Does NOT skip leading whitespace.
  (func $scan_name (export "scan_name") (result i64)
    (local $start i32)
    (local $b i32)
    (local.set $start (i32.load (global.get $VS_scan_ptr)))

    (block $done
      (loop $loop
        (br_if $done (i32.ge_u (i32.load (global.get $VS_scan_ptr)) (i32.load (global.get $VS_scan_end))))
        (local.set $b (i32.load8_u (i32.load (global.get $VS_scan_ptr))))
        (br_if $done (i32.eqz (call $is_ident_byte (local.get $b))))
        (i32.store (global.get $VS_scan_ptr)
          (i32.add (i32.load (global.get $VS_scan_ptr)) (i32.const 1)))
        (br $loop)
      )
    )

    ;; Pack (start, len) as i64
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $start)) (i64.const 32))
      (i64.extend_i32_u (i32.sub (i32.load (global.get $VS_scan_ptr)) (local.get $start))))
  )

  ;; scan_until_terminator() -> i64 (packed: hi=ptr, lo=len)
  ;; Collect body text until the matching ◆, respecting nested operator depth.
  ;; The scanner must be positioned AFTER the opening operator.
  ;; On return, scan_ptr is positioned AFTER the closing ◆.
  ;; Scope-opening operators (need matching ◆): ▼ ▶ ▽ ▷ ◯
  ;; Non-scope operators (no ◆): ▲ △ □
  ;; ◆ decreases depth
  (func $scan_until_terminator (export "scan_until_terminator") (result i64)
    (local $start i32)
    (local $depth i32)
    (local $b i32)
    (local $remaining i32)
    (local $op i32)
    (local $body_end i32)

    (local.set $start (i32.load (global.get $VS_scan_ptr)))
    (local.set $depth (i32.const 1))  ;; we're inside one operator already
    (i32.store (global.get $VS_scan_unterminated) (i32.const 0))

    (block $done
      (loop $loop
        (br_if $done (i32.ge_u (i32.load (global.get $VS_scan_ptr)) (i32.load (global.get $VS_scan_end))))

        (local.set $b (i32.load8_u (i32.load (global.get $VS_scan_ptr))))

        ;; Track newlines
        (if (i32.eq (local.get $b) (i32.const 0x0A))
          (then
            (i32.store (global.get $VS_scan_line)
              (i32.add (i32.load (global.get $VS_scan_line)) (i32.const 1)))
          )
        )

        ;; Check for operator
        (if (i32.eq (local.get $b) (i32.const 0xE2))
          (then
            (local.set $remaining
              (i32.sub (i32.load (global.get $VS_scan_end)) (i32.load (global.get $VS_scan_ptr))))
            (if (i32.ge_u (local.get $remaining) (i32.const 3))
              (then
                (local.set $op (call $is_operator_at (i32.load (global.get $VS_scan_ptr))))
                (if (i32.ne (local.get $op) (i32.const 0))
                  (then
                    (if (i32.eq (local.get $op) (global.get $TOK_TERMINATOR))
                      (then
                        ;; ◆ decreases depth
                        (local.set $depth
                          (i32.sub (local.get $depth) (i32.const 1)))
                        (if (i32.eqz (local.get $depth))
                          (then
                            ;; Found our closing ◆
                            (local.set $body_end (i32.load (global.get $VS_scan_ptr)))
                            ;; Advance past the ◆ (3 bytes)
                            (i32.store (global.get $VS_scan_ptr)
                              (i32.add (i32.load (global.get $VS_scan_ptr)) (i32.const 3)))
                            ;; Return body (start, body_end - start)
                            (return
                              (i64.or
                                (i64.shl (i64.extend_i32_u (local.get $start)) (i64.const 32))
                                (i64.extend_i32_u
                                  (i32.sub (local.get $body_end) (local.get $start)))))
                          )
                        )
                      )
                      (else
                        ;; Only scope-opening operators increase depth:
                        ;; ▼(3) ▶(5) ▽(6) ▷(8) ◯(9)
                        ;; ▲(4) △(7) □(10) do NOT open scopes
                        (if (i32.or
                              (i32.eq (local.get $op) (global.get $TOK_DEFER))
                              (i32.or
                                (i32.or
                                  (i32.eq (local.get $op) (global.get $TOK_STORE))
                                  (i32.eq (local.get $op) (global.get $TOK_EXECUTE)))
                                (i32.or
                                  (i32.eq (local.get $op) (global.get $TOK_IMM_STORE))
                                  (i32.eq (local.get $op) (global.get $TOK_IMM_EXEC)))))
                          (then
                            (local.set $depth
                              (i32.add (local.get $depth) (i32.const 1)))
                          )
                        )
                      )
                    )
                    ;; Skip the 3-byte operator
                    (i32.store (global.get $VS_scan_ptr)
                      (i32.add (i32.load (global.get $VS_scan_ptr)) (i32.const 3)))
                    (br $loop)
                  )
                )
              )
            )
          )
        )

        ;; Regular byte — advance by UTF-8 codepoint width
        (if (i32.lt_u (local.get $b) (i32.const 0x80))
          (then
            (i32.store (global.get $VS_scan_ptr)
              (i32.add (i32.load (global.get $VS_scan_ptr)) (i32.const 1)))
          )
          (else
            (i32.store (global.get $VS_scan_ptr)
              (i32.add (i32.load (global.get $VS_scan_ptr))
                (i32.wrap_i64 (call $utf8_next (i32.load (global.get $VS_scan_ptr)) (i32.load (global.get $VS_scan_end))))))
          )
        )
        (br $loop)
      )
    )

    ;; Ran off end without finding closing ◆ — return everything, and record
    ;; that the scope was left open so the operator that opened it can decide
    ;; whether that is an error.
    (i32.store (global.get $VS_scan_unterminated) (i32.const 1))
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $start)) (i64.const 32))
      (i64.extend_i32_u (i32.sub (i32.load (global.get $VS_scan_ptr)) (local.get $start))))
  )

  ;; scan_next() -> i64 (packed: hi=token_type|val_ptr, lo=val_len)
  ;; Returns one token. Encoding:
  ;;   For EOF:       hi=0, lo=0
  ;;   For NEWLINE:   hi=TOK_NEWLINE, lo=0
  ;;   For OPERATOR:  hi=token_type, lo=0  (scan_ptr advanced past the 3 bytes)
  ;;   For TEXT:      hi=val_ptr, lo=val_len  (token_type stored in scan_last_type)
  ;;
  ;; Caller reads scan_last_type to distinguish TEXT (type=1) from operators.
  ;; TEXT spans from current position to next operator/newline/EOF.
  (func $scan_next (export "scan_next") (result i64)
    (local $b i32)
    (local $remaining i32)
    (local $op i32)
    (local $text_start i32)
;;PROBE_START (call $pb_inc (global.get $PB_scan_next)) ;;PROBE_END

    ;; EOF?
    (if (i32.ge_u (i32.load (global.get $VS_scan_ptr)) (i32.load (global.get $VS_scan_end)))
      (then
        (i32.store (global.get $VS_scan_last_type) (global.get $TOK_EOF))
        (return (i64.const 0))
      )
    )

    (local.set $b (i32.load8_u (i32.load (global.get $VS_scan_ptr))))

    ;; Newline?
    (if (i32.eq (local.get $b) (i32.const 0x0A))
      (then
        (i32.store (global.get $VS_scan_line)
          (i32.add (i32.load (global.get $VS_scan_line)) (i32.const 1)))
        (i32.store (global.get $VS_scan_ptr)
          (i32.add (i32.load (global.get $VS_scan_ptr)) (i32.const 1)))
        (i32.store (global.get $VS_scan_last_type) (global.get $TOK_NEWLINE))
        (return
          (i64.shl (i64.extend_i32_u (global.get $TOK_NEWLINE)) (i64.const 32)))
      )
    )

    ;; CR (skip, treat \r\n as one newline)
    (if (i32.eq (local.get $b) (i32.const 0x0D))
      (then
        (i32.store (global.get $VS_scan_ptr)
          (i32.add (i32.load (global.get $VS_scan_ptr)) (i32.const 1)))
        ;; If followed by \n, that will be picked up next call
        (i32.store (global.get $VS_scan_last_type) (global.get $TOK_NEWLINE))
        (return
          (i64.shl (i64.extend_i32_u (global.get $TOK_NEWLINE)) (i64.const 32)))
      )
    )

    ;; Operator? (3-byte UTF-8 starting with E2)
    (if (i32.eq (local.get $b) (i32.const 0xE2))
      (then
        (local.set $remaining
          (i32.sub (i32.load (global.get $VS_scan_end)) (i32.load (global.get $VS_scan_ptr))))
        (if (i32.ge_u (local.get $remaining) (i32.const 3))
          (then
            (local.set $op (call $is_operator_at (i32.load (global.get $VS_scan_ptr))))
            (if (i32.ne (local.get $op) (i32.const 0))
              (then
                (i32.store (global.get $VS_scan_ptr)
                  (i32.add (i32.load (global.get $VS_scan_ptr)) (i32.const 3)))
                (i32.store (global.get $VS_scan_last_type) (local.get $op))
                (return
                  (i64.shl (i64.extend_i32_u (local.get $op)) (i64.const 32)))
              )
            )
          )
        )
      )
    )

    ;; TEXT: collect bytes until newline, operator, or EOF
    (local.set $text_start (i32.load (global.get $VS_scan_ptr)))
    (block $text_done
      (loop $text_loop
        (br_if $text_done
          (i32.ge_u (i32.load (global.get $VS_scan_ptr)) (i32.load (global.get $VS_scan_end))))

        (local.set $b (i32.load8_u (i32.load (global.get $VS_scan_ptr))))

        ;; Stop on newline/CR
        (br_if $text_done (i32.eq (local.get $b) (i32.const 0x0A)))
        (br_if $text_done (i32.eq (local.get $b) (i32.const 0x0D)))

        ;; Stop on operator
        (if (i32.eq (local.get $b) (i32.const 0xE2))
          (then
            (local.set $remaining
              (i32.sub (i32.load (global.get $VS_scan_end)) (i32.load (global.get $VS_scan_ptr))))
            (if (i32.ge_u (local.get $remaining) (i32.const 3))
              (then
                (local.set $op (call $is_operator_at (i32.load (global.get $VS_scan_ptr))))
                (br_if $text_done (i32.ne (local.get $op) (i32.const 0)))
              )
            )
          )
        )

        ;; Advance by UTF-8 codepoint width
        (if (i32.lt_u (local.get $b) (i32.const 0x80))
          (then
            (i32.store (global.get $VS_scan_ptr)
              (i32.add (i32.load (global.get $VS_scan_ptr)) (i32.const 1)))
          )
          (else
            (i32.store (global.get $VS_scan_ptr)
              (i32.add (i32.load (global.get $VS_scan_ptr))
                (i32.wrap_i64 (call $utf8_next (i32.load (global.get $VS_scan_ptr)) (i32.load (global.get $VS_scan_end))))))
          )
        )
        (br $text_loop)
      )
    )

    (i32.store (global.get $VS_scan_last_type) (global.get $TOK_TEXT))
    ;; Pack (text_start, len) as i64
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $text_start)) (i64.const 32))
      (i64.extend_i32_u
        (i32.sub (i32.load (global.get $VS_scan_ptr)) (local.get $text_start))))
  )

  ;; scan_last_token_type() -> i32: type of last token returned by scan_next
  (func $scan_last_token_type (export "scan_last_token_type") (result i32)
    (i32.load (global.get $VS_scan_last_type))
  )

  ;; ── end SECTION 13: SCANNER ──
