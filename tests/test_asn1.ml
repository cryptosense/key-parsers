open OUnit2

let rsa_suite =
  let open Key_parsers.RSA in
  (* This key pair was generated using openssl genrsa*)
  let expected_public, expected_private =
    let n =
      Z.of_string
        "0x00B0DF8DE301B3E8D567285E754661230BEDD203F62C7FF101AA3BBAA1D268C85883\
         D9DCAD1CB39FC51857B10D4EF6BEF6B4FE720E67C1978E4B7801FECB1FBB29"
    in
    let e = Z.of_string "0x010001" in
    let d =
      Z.of_string
        "0x766C074CB12C2ABD0F07694EEDE3459ACC0D2C17DBAD81C89298D1195D8E486C5567\
         B0A0CDCC88E14F98838C7C093295F57E0366FE0E8C7955D92CA1E86B3C9D"
    in
    let p =
      Z.of_string
        "0x00E6896FAD354609DEF3AA5CE8CDCF91FD1977BEA0D36B131429AF78241290B54B"
    in
    let q =
      Z.of_string
        "0x00C468BF9C0087E05E327B5B91CFA786682EE320979B458DE66850F09CB3EB6CDB"
    in
    let dp =
      Z.of_string
        "0x00C78DA5FE9F83ADDDB0BC024A7E84B3910BAF8C72382F92473CC227D3C9C23B3B"
    in
    let dq =
      Z.of_string
        "0x00AF9317DE43D73329E1A4C679B51083A5346CD320D3ABBCAAC08BC25BC2B66CCB"
    in
    let qinv =
      Z.of_string
        "0x008355897ABCEA9F39B116A241872E971F5F85AD2C435FD085D4C665C58B271B17"
    in
    Public.{ n; e }, Private.{ n; e; d; p; q; dp; dq; qinv; other_primes=[] }
  in
  let cmp = Z.equal in
  let printer = Z.to_string in
  let test_pub ~decode expected der ctxt =
    let real = decode der in
    let open Public in
    Test_util.assert_ok real @@ fun real ->
    assert_equal ~ctxt ~cmp ~printer ~msg:"n" expected.n real.n;
    assert_equal ~ctxt ~cmp ~printer ~msg:"e" expected.e real.e
  in
  let test_priv ~decode expected der ctxt =
    let real = decode der in
    let open Private in
    Test_util.assert_ok real @@ fun real ->
    assert_equal ~ctxt ~cmp ~printer ~msg:"n" expected.n real.n;
    assert_equal ~ctxt ~cmp ~printer ~msg:"e" expected.e real.e;
    assert_equal ~ctxt ~cmp ~printer ~msg:"d" expected.d real.d;
    assert_equal ~ctxt ~cmp ~printer ~msg:"p" expected.p real.p;
    assert_equal ~ctxt ~cmp ~printer ~msg:"q" expected.q real.q;
    assert_equal ~ctxt ~cmp ~printer ~msg:"dp" expected.dp real.dp;
    assert_equal ~ctxt ~cmp ~printer ~msg:"dq" expected.dq real.dq;
    assert_equal ~ctxt ~cmp ~printer ~msg:"qinv" expected.qinv real.qinv
  in
  let pkcs1_suite =
    let private_der = Cstruct.of_string @@ [%blob "../tests/keys/rsa_pkcs1.der"] in
    let public_der = Cstruct.of_string @@ [%blob "../tests/keys/rsa_pkcs1_pub.der"] in
    [ "Private" >:: test_priv ~decode:Private.decode expected_private private_der
    ; "Public" >:: test_pub ~decode:Public.decode expected_public public_der
    ]
  in
  let x509_suite =
    let der = Cstruct.of_string @@ [%blob "../tests/keys/rsa_x509.der"] in
    [ "Public" >:: test_pub ~decode:Key_parsers.X509.decode_rsa expected_public der
    ]
  in
  let pkcs8_suite =
    let der = Cstruct.of_string @@ [%blob "../tests/keys/rsa_pkcs8.der"] in
    [ "Private" >:: test_priv ~decode:Key_parsers.PKCS8.decode_rsa expected_private der
    ]
  in
  [ "PKCS1" >::: pkcs1_suite
  ; "X509" >::: x509_suite
  ; "PKCS8" >::: pkcs8_suite
  ]

let suite =
  [ "RSA" >::: rsa_suite
  ]
