(module
	;; Local, passive HTTP response-header checker. Input is lowercase header text.
	;; scan(ptr, len) returns one bit for each missing defensive header.
	(memory (export "memory") 1)
	(data (i32.const 0) "strict-transport-security:")
	(data (i32.const 32) "content-security-policy:")
	(data (i32.const 64) "x-content-type-options:")
	(data (i32.const 96) "x-frame-options:")
	(data (i32.const 128) "referrer-policy:")
	(data (i32.const 160) "permissions-policy:")

	(func $contains (param $p i32) (param $n i32) (param $q i32) (param $m i32) (result i32)
		(local $i i32) (local $j i32)
		(if (i32.lt_u (local.get $n) (local.get $m)) (then (return (i32.const 0))))
		(block $done
			(loop $outer
				(br_if $done (i32.gt_u (local.get $i) (i32.sub (local.get $n) (local.get $m))))
				(local.set $j (i32.const 0))
				(block $mismatch
					(loop $inner
						(br_if $mismatch (i32.ge_u (local.get $j) (local.get $m)))
						(br_if $mismatch
							(i32.ne
								(i32.load8_u (i32.add (local.get $p) (i32.add (local.get $i) (local.get $j))))
								(i32.load8_u (i32.add (local.get $q) (local.get $j))))
						(local.set $j (i32.add (local.get $j) (i32.const 1)))
						(br $inner)))
				(if (i32.eq (local.get $j) (local.get $m)) (then (return (i32.const 1))))
				(local.set $i (i32.add (local.get $i) (i32.const 1)))
				(br $outer)))
		(i32.const 0))

	;; Result bits: 0 HSTS, 1 CSP, 2 nosniff, 3 frame options,
	;; 4 referrer policy, 5 permissions policy. Findings are advisory only.
	(func (export "scan") (param $ptr i32) (param $len i32) (result i32)
		(local $flags i32)
		(if (i32.eqz (call $contains (local.get $ptr) (local.get $len) (i32.const 0) (i32.const 26)))
			(then (local.set $flags (i32.or (local.get $flags) (i32.const 1)))))
		(if (i32.eqz (call $contains (local.get $ptr) (local.get $len) (i32.const 32) (i32.const 24)))
			(then (local.set $flags (i32.or (local.get $flags) (i32.const 2)))))
		(if (i32.eqz (call $contains (local.get $ptr) (local.get $len) (i32.const 64) (i32.const 23)))
			(then (local.set $flags (i32.or (local.get $flags) (i32.const 4)))))
		(if (i32.eqz (call $contains (local.get $ptr) (local.get $len) (i32.const 96) (i32.const 16)))
			(then (local.set $flags (i32.or (local.get $flags) (i32.const 8)))))
		(if (i32.eqz (call $contains (local.get $ptr) (local.get $len) (i32.const 128) (i32.const 16)))
			(then (local.set $flags (i32.or (local.get $flags) (i32.const 16)))))
		(if (i32.eqz (call $contains (local.get $ptr) (local.get $len) (i32.const 160) (i32.const 19)))
			(then (local.set $flags (i32.or (local.get $flags) (i32.const 32)))))
		(local.get $flags))
)
