open OUnit2

let rsa_suite =
  let open Key_parsers in
  let open Asn1.RSA_CVC in
  let expected_public =
    let n =
      Z.of_string "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    in
    let e = Z.of_string "0x010001" in
    Public.{n; e}
  in
  let cmp = Z.equal in
  let printer = Z.to_string in
  let test_pub ~decode (expected : Public.t) cvc ctxt =
    let real = decode cvc in
    let open Public in
    Test_util.assert_ok real @@ function
      | `RSA real ->
          assert_equal ~ctxt ~cmp ~printer ~msg:"n" expected.n real.n;
          assert_equal ~ctxt ~cmp ~printer ~msg:"e" expected.e real.e
      | `ECDSA _
      | `UNKNOWN ->
          assert_failure ""
  in
  let cvc_suite =
    let cvc = Cstruct.of_string @@ [%blob "../tests/keys/rsa_cvc_dummy.key"] in
    [ "Public" >:: test_pub ~decode:Asn1.CVC.decode expected_public cvc
    ]
  in
  [ "CVC" >::: cvc_suite
  ]

let ecdsa_suite =
  let open Key_parsers in
  let open Asn1.ECDSA_CVC in
  let expected_public =
    let modulus = Z.of_string "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" in
    let coefficient_a = Z.of_string "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" in
    let coefficient_b = Z.of_string "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" in
    let base_point_g = Z.of_string "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" in
    let base_point_r_order = Z.of_string "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" in
    let public_point_y = Z.of_string "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" in
    let cofactor_f = Z.of_string "1" in
    let open Public in
    { modulus
    ; coefficient_a
    ; coefficient_b
    ; base_point_g
    ; base_point_r_order
    ; public_point_y
    ; cofactor_f
    }
  in
  let cmp = Z.equal in
  let printer = Z.to_string in
  let test_pub ~decode (expected : Public.t) cvc ctxt =
    let real = decode cvc in
    let open Public in
    Test_util.assert_ok real @@ function
      | `ECDSA real ->
          assert_equal ~ctxt ~cmp ~printer ~msg:"modulus" expected.modulus real.modulus;
          assert_equal ~ctxt ~cmp ~printer ~msg:"coefficient_a" expected.coefficient_a real.coefficient_a;
          assert_equal ~ctxt ~cmp ~printer ~msg:"coefficient_b" expected.coefficient_b real.coefficient_b;
          assert_equal ~ctxt ~cmp ~printer ~msg:"base_point_g" expected.base_point_g real.base_point_g;
          assert_equal ~ctxt ~cmp ~printer ~msg:"base_point_r_order" expected.base_point_r_order real.base_point_r_order;
          assert_equal ~ctxt ~cmp ~printer ~msg:"public_point_y" expected.public_point_y real.public_point_y;
          assert_equal ~ctxt ~cmp ~printer ~msg:"cofactor_f" expected.cofactor_f real.cofactor_f
      | `RSA _
      | `UNKNOWN ->
          assert_failure "Wrong kind of key."
  in
  let cvc_suite =
    let cvc = Cstruct.of_string @@ [%blob "../tests/keys/ecdsa_cvc_dummy.key"] in
    [ "Public" >:: test_pub ~decode:Asn1.CVC.decode expected_public cvc
    ]
  in
  [ "CVC" >::: cvc_suite
  ]

let suite =
  [ "RSA" >::: rsa_suite
  ; "ECDSA" >::: ecdsa_suite
  ]

