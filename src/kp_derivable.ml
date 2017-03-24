open Bin_prot.Std

let pp_of_to_string to_string fmt x =
  Format.pp_print_string fmt (to_string x)

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

  let bin_writer_t = Bin_prot.Type_class.cnv_writer Z.to_bits bin_writer_string
  let bin_reader_t = Bin_prot.Type_class.cnv_reader Z.of_bits bin_reader_string
  let bin_size_t = bin_writer_t.Bin_prot.Type_class.size
  let bin_write_t = bin_writer_t.Bin_prot.Type_class.write
  let bin_read_t = bin_reader_t.Bin_prot.Type_class.read
  let __bin_read_t__ = bin_reader_t.Bin_prot.Type_class.vtag_read
  let bin_t = Bin_prot.Type_class.{ reader = bin_reader_t; writer =  bin_writer_t}
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

  let bin_writer_t = Bin_prot.Type_class.cnv_writer Cstruct.to_string bin_writer_string
  let bin_reader_t = Bin_prot.Type_class.cnv_reader Cstruct.of_string bin_reader_string
  let bin_size_t = bin_writer_t.Bin_prot.Type_class.size
  let bin_write_t = bin_writer_t.Bin_prot.Type_class.write
  let bin_read_t = bin_reader_t.Bin_prot.Type_class.read
  let __bin_read_t__ = bin_reader_t.Bin_prot.Type_class.vtag_read
  let bin_t = Bin_prot.Type_class.{ reader = bin_reader_t; writer =  bin_writer_t}
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

  let bin_writer_t = Bin_prot.Type_class.cnv_writer Asn.OID.to_string bin_writer_string
  let bin_reader_t = Bin_prot.Type_class.cnv_reader Asn.OID.of_string bin_reader_string
  let bin_size_t = bin_writer_t.Bin_prot.Type_class.size
  let bin_write_t = bin_writer_t.Bin_prot.Type_class.write
  let bin_read_t = bin_reader_t.Bin_prot.Type_class.read
  let __bin_read_t__ = bin_reader_t.Bin_prot.Type_class.vtag_read
  let bin_t = Bin_prot.Type_class.{ reader = bin_reader_t; writer =  bin_writer_t}
end
