open OUnit2
open Test_helpers

module Rsa = struct
  (* This key pair was generated using openssl genrsa*)
  let expected_public, expected_private =
    let n =
      Z.of_string
        "0x00B0DF8DE301B3E8D567285E754661230BEDD203F62C7FF101AA3BBAA1D268C85883D9DCAD1CB39FC51857B10D4EF6BEF6B4FE720E67C1978E4B7801FECB1FBB29"
    in
    let e = Z.of_string "0x010001" in
    let d =
      Z.of_string
        "0x766C074CB12C2ABD0F07694EEDE3459ACC0D2C17DBAD81C89298D1195D8E486C5567B0A0CDCC88E14F98838C7C093295F57E0366FE0E8C7955D92CA1E86B3C9D"
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
    let open Key_parsers.Asn1.Rsa in
    (Public.{n; e}, Private.{n; e; d; p; q; dp; dq; qinv; other_primes = []})

  let test_pub ~decode expected der ctxt =
    let open Key_parsers.Asn1.Rsa in
    let actual = decode der in
    Test_util.assert_ok actual @@ fun actual ->
    assert_equal ~ctxt ~cmp:[%eq: Public.t] ~printer:[%show: Public.t] expected
      actual

  let test_error ~decode expected der ctxt =
    let actual = decode der in
    Test_util.assert_error actual @@ fun actual ->
    assert_equal ~ctxt ~cmp:[%eq: string] ~printer:[%show: string] expected
      actual

  let test_priv ~decode expected der ctxt =
    let open Key_parsers.Asn1.Rsa in
    let actual = decode der in
    Test_util.assert_ok actual @@ fun actual ->
    assert_equal ~ctxt ~cmp:[%eq: Private.t] ~printer:[%show: Private.t]
      expected actual

  let test_pkcs1 =
    let open Key_parsers.Asn1.Rsa in
    "PKCS#1"
    >::: [ "Private"
           >:: test_priv ~decode:Private.decode expected_private
                 (fixture "rsa_pkcs1.der")
         ; "Public"
           >:: test_pub ~decode:Public.decode expected_public
                 (fixture "rsa_pkcs1_pub.der") ]

  let test_x509 =
    let decode = Key_parsers.Asn1.X509.decode_rsa in
    "X509"
    >::: [ "Public" >:: test_pub ~decode expected_public (fixture "rsa_x509.der")
         ; "Without parameters"
           >:: test_pub ~decode expected_public
                 (fixture "rsa_x509_no_params.der") ]

  let test_pkcs8 =
    let decode = Key_parsers.Asn1.PKCS8.decode_rsa in
    "PKCS#8"
    >::: [ "Private"
           >:: test_priv ~decode expected_private (fixture "rsa_pkcs8.der") ]

  let test_negative_key =
    let decode = Key_parsers.Asn1.X509.decode_rsa in
    "X509"
    >::: [ "Negative Public Key"
           >:: test_error ~decode "X509 RSA key: Negative modulus"
                 (fixture "negative_rsa.der") ]

  let suite = "Rsa" >::: [test_pkcs1; test_x509; test_pkcs8; test_negative_key]
end

let dsa_suite =
  let open Key_parsers.Asn1.Dsa in
  (* These parameters and key pair were generated using openssl dsaparam and gendsa *)
  let p =
    Z.of_string
      "0x00E21ECE0A801FFBFBA42C78331538C38E004BF7EBD2F882B5AAB6B17AD0F9BE7352DFEB7522BCA514884CBBC78197B3889DF954D6C5E06EF824B7DD54F256A6AF04B77D1A683E725AF3283C4A55A88FCEAACE54328FDF99A690A353E1D07041DD4D0EC391C8B1249E52541D7BC95229A783AA5C3BBFA0F5C21203B32C3BC2058D"
  in
  let q = Z.of_string "0x00B77D5A19B02F7827EE7086E58D669768BCBF6133" in
  let g =
    Z.of_string
      "0x00D827687BE818D99E654B04638F9B4C88C446CDDCDF5EFBB82C6834FDA74ECD9D119EAF7CF749270043068CA2E5A844C77B24E5429BD2DBB05C50DB96CD04BBFA769E52D4E8367AE0D926C7B9E7FE2464951BA2F0A190B0DD1E4540D85F6A89A01FD047972EA7FB21AD137A09C0B10087F627DB21A5F7630AC30A421F0585D1BC"
  in

  let dsa_public_key =
    Z.of_string
      "0x3D43977A2859A30F8BF890597DA1F24FB0978079770EDAAFCEFE4F6A8BB0C07DDBEF1B4D9FD487BEE92C230085365431215F1935507F8543D4111A59071B241064589ADCF8FF5037FA8C0FC590C6A41B381089BEC44979CF3B4B9F6EE93CA3D6C9C3AABF0242F64B1B1F9602E0C7A51E9C62E995F20A314B2EB642D7260149A0"
  in

  let dsa_private_key =
    Z.of_string "0x515347B306C0D6A4C172AFCB92E1147477EF7ADB"
  in

  let expected_dsa =
    let open Key_parsers.Asn1 in
    Dsa_private_key.
      {p; q; g; public_key = dsa_public_key; private_key = dsa_private_key}
  in

  let dsa_private_suite =
    let test expected_dsa der ctxt =
      let open Key_parsers.Asn1 in
      let actual = Dsa_private_key.decode der in
      Test_util.assert_ok actual @@ fun actual ->
      assert_equal ~ctxt ~cmp:[%eq: Dsa_private_key.t]
        ~printer:[%show: Dsa_private_key.t] expected_dsa actual
    in
    let der = fixture "dsa_private_key.der" in
    ["Private_key" >:: test expected_dsa der]
  in

  let expected_params = Params.{p; q; g} in
  let expected_public = (expected_params, dsa_public_key) in
  let expected_private = (expected_params, dsa_private_key) in
  let cmp = Z.equal in
  let printer = Z.to_string in
  let test_params expected real ctxt =
    let open Params in
    assert_equal ~ctxt ~cmp ~printer ~msg:"p" expected.p real.p;
    assert_equal ~ctxt ~cmp ~printer ~msg:"q" expected.q real.q;
    assert_equal ~ctxt ~cmp ~printer ~msg:"g" expected.g real.g
  in
  let test ~typ ~decode (expected_params, expected_key) der ctxt =
    let real = decode der in
    let msg =
      match typ with
      | `Public -> "y"
      | `Private -> "x"
    in
    Test_util.assert_ok real @@ fun (real_params, real_key) ->
    test_params expected_params real_params ctxt;
    assert_equal ~ctxt ~cmp ~printer ~msg expected_key real_key
  in
  let x509_suite =
    let typ = `Public in
    let der = fixture "dsa_x509.der" in
    [ "Public"
      >:: test ~typ ~decode:Key_parsers.Asn1.X509.decode_dsa expected_public der
    ]
  in
  let pkcs8_suite =
    let typ = `Private in
    let der = fixture "dsa_pkcs8.der" in
    [ "Private"
      >:: test ~typ ~decode:Key_parsers.Asn1.PKCS8.decode_dsa expected_private
            der ]
  in

  [ "DSA_PRIVATE" >::: dsa_private_suite
  ; "X509" >::: x509_suite
  ; "PKCS8" >::: pkcs8_suite ]

let ec_suite =
  let open Key_parsers.Asn1.Ec in
  let p256v1_oid = Asn.OID.(base 1 2 <|| [840; 10045; 3; 1; 7]) in
  let exp_named_params = Params.Named p256v1_oid in
  let test_params expected real ctxt =
    let printer = Params.show in
    let cmp p p' = Params.compare p p' = 0 in
    assert_equal ~ctxt ~cmp ~printer ~msg:"params" expected real
  in
  let param_suite =
    let exp_specified_prime =
      let field =
        let p =
          Z.of_string
            "0x00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
        in
        Field.Prime p
      in
      let curve =
        let a =
          Test_util.cstruct_of_hex
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"
        in
        let b =
          Test_util.cstruct_of_hex
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
        in
        let seed =
          Some
            (Test_util.cstruct_of_hex "C49D360886E704936A6678E1139D26B7819F7E90")
        in
        Specified_domain.{a; b; seed}
      in
      let base =
        Test_util.cstruct_of_hex
          "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
      in
      let order =
        Z.of_string
          "0x00FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
      in
      let cofactor = Some (Z.of_int 1) in
      Params.Specified Specified_domain.{field; curve; base; order; cofactor}
    in
    let exp_specified_binary =
      let field =
        let m = Z.of_int 113 in
        let basis = Field.TP (Z.of_int 9) in
        Field.(C_two {m; basis})
      in
      let curve =
        let a = Test_util.cstruct_of_hex "3088250CA6E7C7FE649CE85820F7" in
        let b = Test_util.cstruct_of_hex "E8BEE4D3E2260744188BE0E9C723" in
        let seed =
          Some
            (Test_util.cstruct_of_hex "10E723AB14D696E6768756151756FEBF8FCB49A9")
        in
        Specified_domain.{a; b; seed}
      in
      let base =
        Test_util.cstruct_of_hex
          "04009D73616F35F4AB1407D73562C10F00A52830277958EE84D1315ED31886"
      in
      let order = Z.of_string "0x0100000000000000D9CCEC8A39E56F" in
      let cofactor = Some (Z.of_int 2) in
      Params.Specified Specified_domain.{field; curve; base; order; cofactor}
    in
    let test_params expected der ctxt =
      let real = Params.decode der in
      Test_util.assert_ok real @@ fun real -> test_params expected real ctxt
    in
    let named_der = fixture "p256v1_named_param.der" in
    let prime_der = fixture "p256v1_explicit_param.der" in
    let bin_der = fixture "sect113r1_explicit_param.der" in
    [ "Named" >:: test_params exp_named_params named_der
    ; "Specifed"
      >::: [ "PrimeField" >:: test_params exp_specified_prime prime_der
           ; "BinaryField" >:: test_params exp_specified_binary bin_der ] ]
  in
  let h =
    Test_util.cstruct_of_hex
      "04DB81688B7871A0762ADCDC6109F37C45AA689BDB300E3036614C8FE21E7AB1C1E8A133D358F0ED65B478D97064535ECE5BC2809A2BC974D25639DEFE5D38EE89"
  in
  let exp_public = (exp_named_params, h) in
  let exp_private =
    let params = None in
    let k =
      Test_util.cstruct_of_hex
        "3F05F839F41567FF8A2D2ACA64BA92AEC698B43C52D4CF0D2264F4615F07FB86"
    in
    let public_key = Some h in
    (exp_named_params, Private.{k; params; public_key})
  in
  let x509_suite =
    let test (expected_params, expected_key) der ctxt =
      let printer = Public.show in
      let cmp pub pub' = Public.compare pub pub' = 0 in
      let real = Key_parsers.Asn1.X509.decode_ec der in
      Test_util.assert_ok real @@ fun (real_params, real_key) ->
      test_params expected_params real_params ctxt;
      assert_equal ~ctxt ~cmp ~printer ~msg:"H" expected_key real_key
    in
    let der = fixture "p256v1_x509.der" in
    ["Public" >:: test exp_public der]
  in
  let pkcs8_suite =
    let test (expected_params, expected_key) der ctxt =
      let printer = Private.show in
      let cmp priv priv' = Private.compare priv priv' = 0 in
      let real = Key_parsers.Asn1.PKCS8.decode_ec der in
      Test_util.assert_ok real @@ fun (real_params, real_key) ->
      test_params expected_params real_params ctxt;
      assert_equal ~ctxt ~cmp ~printer ~msg:"privateKey" expected_key real_key
    in
    let der = fixture "p256v1_pkcs8.der" in
    ["Private" >:: test exp_private der]
  in
  ["Params" >::: param_suite; "X509" >::: x509_suite; "PKCS8" >::: pkcs8_suite]

let dh_suite =
  let open Key_parsers.Asn1.Dh in
  (* These parameters and key pair were generated using openssl dhparam and genpkey *)
  let expected_params =
    let p =
      Z.of_string
        "0x00FD5E02F538091F7380991F204E931C62633358124FA1C3DE6A9F852B2C621F040F44B56F6C6605CFBBC4CF4ECD449BB2889CEA53E0FF88F1FE8D9471030EE893"
    in
    let g = Z.of_string "2" in
    Params.{p; g; l = None}
  in
  let expected_public =
    let y =
      Z.of_string
        "0x00DBF090700954EA1B1B05DBC33494D0EBC8E2C5E66AFB24D322877021C76C634A9227D5E6B77F15673AF5814DAA7106F8F040F89DDC3294362888B934F4D8E95E"
    in
    (expected_params, y)
  in
  let expected_private =
    let x =
      Z.of_string
        "0x4BE30C58EB827B66F853E57AC44E0D42850C284EF08D8406EFBED228A47F93667CCA1A84F1496AAFF545212B96D2E66FB8DE4AB20DB7E6747D21E8B1CFE040BE"
    in
    (expected_params, x)
  in
  let cmp = Z.equal in
  let printer = Z.to_string in
  let test_params expected real ctxt =
    let open Params in
    assert_equal ~ctxt ~cmp ~printer ~msg:"p" expected.p real.p;
    assert_equal ~ctxt ~cmp ~printer ~msg:"g" expected.g real.g;
    assert_equal ~ctxt
      ~cmp:(Test_util.equal_options ~equal:Z.equal)
      ~printer:(function
        | Some x -> Z.to_string x
        | None -> "nothing")
      ~msg:"l" expected.l real.l
  in
  let test ~typ ~decode (expected_params, expected_key) der ctxt =
    let real = decode der in
    let msg =
      match typ with
      | `Public -> "y"
      | `Private -> "x"
    in
    Test_util.assert_ok real @@ fun (real_params, real_key) ->
    test_params expected_params real_params ctxt;
    assert_equal ~ctxt ~cmp ~printer ~msg expected_key real_key
  in
  let x509_suite =
    let typ = `Public in
    let der = fixture "dh_public.der" in
    [ "Public"
      >:: test ~typ ~decode:Key_parsers.Asn1.X509.decode_dh expected_public der
    ]
  in
  let pkcs8_suite =
    let typ = `Private in
    let der = fixture "dh_private.der" in
    [ "Private"
      >:: test ~typ ~decode:Key_parsers.Asn1.PKCS8.decode_dh expected_private
            der ]
  in
  ["X509" >::: x509_suite; "PKCS8" >::: pkcs8_suite]

let suite =
  [Rsa.suite; "Dsa" >::: dsa_suite; "Ec" >::: ec_suite; "Dh" >::: dh_suite]
