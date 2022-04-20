open OUnit2

let read_cstruct path =
  let ic = open_in path in
  let len = in_channel_length ic in
  let s = really_input_string ic len in
  close_in ic;
  Cstruct.of_string s

let fixture name =
  let path = Printf.sprintf "keys/%s" name in
  read_cstruct path

let assert_ok r test =
  match r with
  | Result.Ok x -> test x
  | Result.Error s -> assert_failure s

let assert_error r test =
  match r with
  | Result.Ok _ -> assert_failure "Expected error"
  | Result.Error s -> test s

let equal_options ~(equal : 'a -> 'a -> bool) (a : 'a option) (b : 'a option) =
  match (a, b) with
  | Some x, Some y -> equal x y
  | None, None -> true
  | _, _ -> false

let cstruct_of_hex str = `Hex (String.lowercase_ascii str) |> Hex.to_cstruct
