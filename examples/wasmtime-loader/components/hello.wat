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

  ;; Canonical ABI adapter functions
  (func $get-msg (result string)
    (canon lift (core func $hello_inst "get-message") (memory $hello_inst "memory") string-encoding=utf8)
  )

  ;; Call host print with our message
  (start (func
    (let (local $msg string) (call $get-msg))
    (call $host "print" (local.get $msg))
  ))
)
