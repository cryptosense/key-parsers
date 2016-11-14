#use "topfind"
#require "topkg"
open Topkg

let api = ["Key_parsers"]

let () =
  Pkg.describe "key-parsers" @@ fun c ->
  Ok [ Pkg.mllib ~api "src/key_parsers.mllib"
     ; Pkg.test "tests/test_all"
     ]
