open OUnit2

let suite =
  "Key-parsers"
  >::: [ "LTPA" >::: Test_ltpa.suite
       ; "ASN1" >::: Test_asn1.suite
       ; "CVC" >::: Test_cvc.suite
       ; "PGP" >::: Test_pgp.suite
       ; "Safe Cstruct" >::: Test_safe_cstruct.suite ]

let _ = run_test_tt_main suite
