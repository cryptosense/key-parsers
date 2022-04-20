let to_string ?(off = 0) t =
    try
        Cstruct.to_string ~off t
    with
    | Invalid_argument _ -> ""

let length = Cstruct.length

let shift t i =
    try
        Cstruct.shift t i
    with
    | Invalid_argument _ -> Cstruct.empty

let sub t i j =
    try
        Cstruct.sub t i j
    with
    | Invalid_argument _ -> Cstruct.empty

let get_uint8 t i =
    try
        Cstruct.get_uint8 t i
    with
    | Invalid_argument _ -> 0

module BE = struct
    let get_uint16 t i =
        try
            Cstruct.BE.get_uint16 t i
        with
        | Invalid_argument _ -> 0

    let get_uint32 t i =
        try
            Cstruct.BE.get_uint32 t i
        with
        | Invalid_argument _ -> Int32.of_int 0

    let get_uint64 t i =
        try
            Cstruct.BE.get_uint64 t i
        with
        | Invalid_argument _ -> Int64.of_int 0
end
