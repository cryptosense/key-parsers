val length : Cstruct.t -> int

val to_string : ?off:int ->  Cstruct.t -> string

val shift : Cstruct.t -> int -> Cstruct.t

val get_uint8 : Cstruct.t -> int -> int

val sub : Cstruct.t -> int -> int -> Cstruct.t

module BE : sig
    val get_uint16 : Cstruct.t -> int -> int

    val get_uint32 : Cstruct.t -> int -> int32

    val get_uint64 : Cstruct.t -> int -> int64
end
