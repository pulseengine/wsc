;; Component Model hello world example
(component
  ;; Import host print function
  (import "host" (instance $host
    (export "print" (func (param string)))
  ))

  ;; Core module that implements the logic
  (core module $hello
    ;; Memory for string data
    (memory (export "memory") 1)

    ;; Hello message stored at offset 0
    (data (i32.const 0) "Hello from signed component!")

    ;; Export function that returns pointer and length
    (func (export "get-message") (result i32 i32)
      i32.const 0   ;; pointer to string
      i32.const 28  ;; length of string
    )
  )

  ;; Instantiate the core module
  (core instance $hello_inst (instantiate $hello))

  ;; Canonical ABI adapter to lift core function to component function
  (func $get-msg (result string)
    (canon lift (core func $hello_inst "get-message") (memory $hello_inst "memory") string-encoding=utf8)
  )

  ;; Adapter to call host print
  (func $print-msg
    (param $msg string)
    (call $host "print" (local.get $msg))
  )

  ;; Component start function: get message and print it
  (func $main
    (call $print-msg (call $get-msg))
  )

  (start $main)
)
