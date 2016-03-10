open OUnit2

let assert_ok r test =
  match r with
  | Result.Ok x -> test x
  | Result.Error s -> assert_failure s
