(module
	;; Conservative WebAssembly container triage. This reports review indicators,
	;; not confirmed vulnerabilities; section IDs are parsed with their lengths.
	;; scan(ptr, len) flags: 1=invalid header, 2=malformed section framing,
	;; 4=imports, 8=start section, 16=memory section, 32=code section.
	(memory (export "memory") 1)

	(func (export "scan") (param $ptr i32) (param $len i32) (result i32)
		(local $flags i32)
		(local $pos i32)
		(local $sid i32)
		(local $size i32)
		(local $shift i32)
		(local $count i32)
		(local $byte i32)
		(local $end i32)

		(if (i32.lt_u (local.get $len) (i32.const 8))
			(then (return (i32.const 1))))
		(if (i32.or
					(i32.or
						(i32.ne (i32.load8_u (local.get $ptr)) (i32.const 0))
						(i32.ne (i32.load8_u (i32.add (local.get $ptr) (i32.const 1))) (i32.const 97)))
					(i32.or
						(i32.ne (i32.load8_u (i32.add (local.get $ptr) (i32.const 2))) (i32.const 115))
						(i32.ne (i32.load8_u (i32.add (local.get $ptr) (i32.const 3))) (i32.const 109))))
			(then (return (i32.const 1))))
		(if (i32.or
					(i32.ne (i32.load8_u (i32.add (local.get $ptr) (i32.const 4))) (i32.const 1))
					(i32.or
						(i32.ne (i32.load8_u (i32.add (local.get $ptr) (i32.const 5))) (i32.const 0))
						(i32.or
							(i32.ne (i32.load8_u (i32.add (local.get $ptr) (i32.const 6))) (i32.const 0))
							(i32.ne (i32.load8_u (i32.add (local.get $ptr) (i32.const 7))) (i32.const 0)))))
			(then (return (i32.const 1))))

		(local.set $pos (i32.const 8))
		(block $finish
			(loop $sections
				(br_if $finish (i32.ge_u (local.get $pos) (local.get $len)))
				(local.set $sid (i32.load8_u (i32.add (local.get $ptr) (local.get $pos))))
				(local.set $pos (i32.add (local.get $pos) (i32.const 1)))
				(local.set $size (i32.const 0))
				(local.set $shift (i32.const 0))
				(local.set $count (i32.const 0))
				(block $leb_done
					(loop $leb
						(if (i32.ge_u (local.get $pos) (local.get $len))
							(then
								(local.set $flags (i32.or (local.get $flags) (i32.const 2)))
								(br $finish)))
						(local.set $byte (i32.load8_u (i32.add (local.get $ptr) (local.get $pos))))
						(local.set $pos (i32.add (local.get $pos) (i32.const 1)))
						(local.set $count (i32.add (local.get $count) (i32.const 1)))
						(if (i32.gt_u (local.get $count) (i32.const 5))
							(then
								(local.set $flags (i32.or (local.get $flags) (i32.const 2)))
								(br $finish)))
						(if (i32.and
									(i32.eq (local.get $count) (i32.const 5))
									(i32.ne (i32.and (local.get $byte) (i32.const 240)) (i32.const 0)))
							(then
								(local.set $flags (i32.or (local.get $flags) (i32.const 2)))
								(br $finish)))
						(local.set $size
							(i32.or (local.get $size)
								(i32.shl (i32.and (local.get $byte) (i32.const 127)) (local.get $shift))))
						(if (i32.eqz (i32.and (local.get $byte) (i32.const 128)))
							(then (br $leb_done)))
						(local.set $shift (i32.add (local.get $shift) (i32.const 7)))
						(br $leb)))

				(if (i32.eq (local.get $sid) (i32.const 2))
					(then (local.set $flags (i32.or (local.get $flags) (i32.const 4)))))
				(if (i32.eq (local.get $sid) (i32.const 8))
					(then (local.set $flags (i32.or (local.get $flags) (i32.const 8)))))
				(if (i32.eq (local.get $sid) (i32.const 5))
					(then (local.set $flags (i32.or (local.get $flags) (i32.const 16)))))
				(if (i32.eq (local.get $sid) (i32.const 10))
					(then (local.set $flags (i32.or (local.get $flags) (i32.const 32)))))

				(local.set $end (i32.add (local.get $pos) (local.get $size)))
				(if (i32.or
							(i32.lt_u (local.get $end) (local.get $pos))
							(i32.gt_u (local.get $end) (local.get $len)))
					(then
						(local.set $flags (i32.or (local.get $flags) (i32.const 2)))
						(br $finish)))
				(local.set $pos (local.get $end))
				(br $sections)))
		(local.get $flags))
)
