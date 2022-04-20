open OUnit2

let test_safe_shift =
  let test ~input ~shift ~expected ctxt =
    let input = Cstruct.of_string input in
    let result =
      Cstruct.to_string (Key_parsers.Safe_cstruct.shift input shift)
    in
    assert_equal ~printer:[%show: string] ~ctxt result expected
  in
  [ "Basic test" >:: test ~input:"test" ~shift:2 ~expected:"st"
  ; "Bad shift test" >:: test ~input:"test" ~shift:10 ~expected:""
  ; "Negative shift test" >:: test ~input:"test" ~shift:(-2) ~expected:"" ]

let suite = ["Safe shift" >::: test_safe_shift]
