open Bin_prot.Std

let pp_of_to_string to_string fmt x =
  Format.pp_print_string fmt (to_string x)

module Bin_string = struct
  type t = string
  [@@deriving bin_io]
end

module Z = struct
  type t = Z.t
  [@@deriving eq,ord]

  let show = Z.to_string
  let pp = pp_of_to_string show

  let of_yojson = function
    | `String s -> Result.Ok (Z.of_string s)
    | _ -> Result.Error "Cannot convert this json value to Z.t"

  let to_yojson z =
    `String (Z.to_string z)

  include Bin_prot.Utils.Make_binable
      (struct
        module Binable = Bin_string
        type t = Z.t
        let to_binable = Z.to_string
        let of_binable = Z.of_string
      end)
end

module Cstruct = struct
  type t = Cstruct.t
  [@@deriving eq,ord]

  let to_hex_string cs =
    let buf = Buffer.create 0 in
    Cstruct.hexdump_to_buffer buf cs;
    Buffer.contents buf

  let show = to_hex_string
  let pp = pp_of_to_string show

  let to_yojson cs =
    `String (Cstruct.to_string cs)

  let of_yojson = function
    | `String s -> Result.Ok (Cstruct.of_string s)
    | _ -> Result.Error "Cannot convert this json value to Cstruct.t"

  include Bin_prot.Utils.Make_binable
      (struct
        module Binable = Bin_string
        type t = Cstruct.t
        let to_binable = Cstruct.to_string
        let of_binable s = Cstruct.of_string s
      end)
end

module Asn_OID = struct
  type t = Asn.OID.t
  let show = Asn.OID.to_string
  let pp = pp_of_to_string show
  let compare a b =
    String.compare (show a) (show b)
  let equal a b = compare a b = 0

  let of_yojson = function
    | `String s -> Result.Ok (Asn.OID.of_string s)
    | _ -> Result.Error "Cannot convert this json value to Asn.OID.t"

  let to_yojson oid =
    `String (Asn.OID.to_string oid)

  include Bin_prot.Utils.Make_binable
      (struct
        module Binable = Bin_string
        type t = Asn.OID.t
        let to_binable = Asn.OID.to_string
        let of_binable s = Asn.OID.of_string s
      end)
end
