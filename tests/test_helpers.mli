val fixture : string -> Cstruct.t
(** Reads a file in [tests/keys] *)

val assert_ok : ('a, string) result -> ('a -> 'b) -> 'b
val assert_error : ('a, 'b) result -> ('b -> 'c) -> 'c
val equal_options : equal:('a -> 'a -> bool) -> 'a option -> 'a option -> bool
val cstruct_of_hex : string -> Cstruct.t
