open OUnit2

let suite =
  "Key-parsers" >:::
  [ "LTPA" >::: Test_ltpa.suite
  ]

let _ = run_test_tt_main suite
