let try_with_asn f = try Result.Ok (f ()) with Asn.Parse_error s -> Result.Error s
let raise_asn f = match f () with Result.Ok x -> x | Result.Error s -> Asn.parse_error s

let pp_of_to_string to_string fmt x =
  Format.pp_print_string fmt (to_string x)

module Asn = struct
  include (Asn : module type of Asn with module OID := Asn.OID and type 'a t = 'a Asn.t)

  module OID = struct
    include Asn.OID
    let pp = pp_of_to_string to_string
    let compare a b =
      String.compare (to_string a) (to_string b)

    let of_yojson = function
      | `String s -> Result.Ok (Asn.OID.of_string s)
      | _ -> Result.Error "Cannot convert this json value to Asn.OID.t"

    let to_yojson oid =
      `String (Asn.OID.to_string oid)
  end
end

module Z = struct
  include Z
  let pp = pp_of_to_string to_string

  let of_yojson = function
    | `String s -> Result.Ok (Z.of_string s)
    | _ -> Result.Error "Cannot convert this json value to Z.t"

  let to_yojson z =
    `String (Z.to_string z)
end

let base_rsa_oid = Asn.OID.of_string "0.4.0.127.0.7.2.2.2.1"
let base_ecdsa_oid = Asn.OID.of_string "0.4.0.127.0.7.2.2.2.2"

let rsa_oids =
  let open Asn.OID in
  [ base_rsa_oid
  ; base_rsa_oid <| 1
  ; base_rsa_oid <| 2
  ; base_rsa_oid <| 3
  ; base_rsa_oid <| 4
  ; base_rsa_oid <| 5
  ; base_rsa_oid <| 6
  ]

let ecdsa_oids =
  let open Asn.OID in
  [ base_ecdsa_oid
  ; base_ecdsa_oid <| 1
  ; base_ecdsa_oid <| 2
  ; base_ecdsa_oid <| 3
  ; base_ecdsa_oid <| 4
  ; base_ecdsa_oid <| 5
  ]

type t =
  [ `RSA of Z.t * Z.t | `ECDSA of Z.t * Z.t * Z.t * Z.t * Z.t * Z.t * Z.t  | `UNKNOWN ]

type algo_typ =
  | RSA of Asn.OID.t
  | ECDSA of Asn.OID.t
  | Unknown of Asn.OID.t

type parser_state =
  | Init
  | Type
  | Length
  | Value of int

let cvc_object_types =
  [ 0x7F49, (`PUBLIC_KEY, true)
  ; 0x06, (`OID, false)
  ; 0x81, (`MODULUS, false)
  ; 0x82, (`EXPONENT, false)
  ; 0x82, (`COEFFICIENT_A, false)
  ; 0x83, (`COEFFICIENT_B, false)
  ; 0x84, (`BASE_POINT_G, false)
  ; 0x85, (`BASE_POINT_R_ORDER, false)
  ; 0x86, (`PUBLIC_POINT_Y, false)
  ; 0x87, (`COFACTOR_F, false)
  ]

let find_cvc_object_type tag =
  let code = Cstruct.get_uint8 tag 0 in
  try code, List.assoc code cvc_object_types
  with Not_found ->
    let code =
      let msb = code * 0x100 in
      let lsb = Cstruct.get_uint8 tag 1 in
      msb + lsb
    in
    code, List.assoc code cvc_object_types

(* utility function to parse a big-endian blob as a Z.t *)
let atoz_bigendian s =
  let reverse s =
    let n = String.length s in
    String.init n (fun i -> s.[n-1-i])
  in
  Z.of_bits @@ reverse @@ Cstruct.to_string s

let grammar =
  let open Asn in
  let f = function
    | oid when List.mem oid rsa_oids -> RSA oid
    | oid when List.mem oid ecdsa_oids -> ECDSA oid
    | oid -> Unknown oid in
  let g = function
    | RSA oid -> oid
    | ECDSA oid -> oid
    | Unknown oid -> oid in
  map f g oid

let decode_oid str =
  let t, left = Asn.(decode_exn (codec ber grammar) str) in
  if Cstruct.len left = 0 then t
  else Asn.parse_error "CVC: OID with leftover"

let decode bytes =
  let buffer = Cstruct.create 4_096 in
  (* FSM to produce `Type ..., `Length ..., `Value ... tokens from a blob.
   * This tries to exploit tailcall recursion as much as possible in order to
   * avoid a stack explosion
   *)
  let rec tokenize ~acc bytes i lim state = function
    | Init ->
        if i >= lim then List.rev acc
        else tokenize ~acc bytes i lim None Type
    | Type ->
        Cstruct.blit bytes i buffer 0 2;
        let cvc_type = find_cvc_object_type buffer in
        let acc = `Type cvc_type :: acc in
        begin match cvc_type with
          | tag, _ when tag <= 0xff ->
              let i = i + 1 in
              (tokenize[@tailcall]) ~acc bytes i lim (Some cvc_type) Length
          | tag, _ ->
              let i = i + 2 in
              (tokenize[@tailcall]) ~acc bytes i lim (Some cvc_type) Length
        end
    | Length ->
        let code = Cstruct.get_uint8 bytes i in
        if code < 0x80
        then begin
          let i = i + 1 in
          (tokenize[@tailcall]) ~acc:((`Length code) :: acc) bytes i lim state (Value code)
        end
        else
          begin match code with
            | 0x81 ->
                let code = Cstruct.get_uint8 bytes (i + 1) in
                let i = i + 2 in
                (tokenize[@tailcall]) ~acc:((`Length code) :: acc) bytes i lim state (Value code)
            | 0x82 ->
                let code = Cstruct.BE.get_uint16 bytes (i + 1) in
                let i = i + 3 in
                (tokenize[@tailcall]) ~acc:((`Length code) :: acc) bytes i lim state (Value code)
            | _ ->
                raise (Failure "Invalid LENGTH field in TLV encoded CVC data")
          end
    | Value length ->
        let is_rec =
          match state with
            | None -> false
            | Some (_, (_, x)) -> x
        in
        let acc =
          if is_rec
          then
            `Value (tokenize ~acc:[] bytes i (i + length) None Init) :: acc
          else
            let bytes' =
              Cstruct.sub bytes i length
            in
            `Bytes bytes' :: acc
        in
        (if length + i >= Cstruct.len bytes then List.rev acc else (tokenize[@tailcall]) ~acc bytes (i + length) lim None Init)
  in
  let tokens = tokenize ~acc:[] bytes 0 (Cstruct.len bytes) None Init in
  let rec parse = function
    | `Type (_, (`PUBLIC_KEY, _)) :: `Length _ :: `Value ls :: _ ->
        parse ls
    | `Type (_, (`OID, _)) :: `Length _ :: `Bytes bytes :: tl ->
        let bytes =
          let prefix =
            Printf.sprintf "\006%c" (Char.chr (Cstruct.len bytes))
            |> Cstruct.of_string
          in
          Cstruct.append prefix bytes
        in
        `Oid (decode_oid bytes) :: parse tl
    | `Type (_, (`MODULUS, _)) :: `Length _ :: `Bytes bytes :: tl ->
        `Modulus (atoz_bigendian bytes) :: parse tl
    | `Type (0x82, ((*`EXPONENT*) _ , _)) :: `Length _ :: `Bytes bytes :: tl ->
        `Exponent (atoz_bigendian bytes) :: parse tl
    | `Type (_, (`COEFFICIENT_B, _)) :: `Length _ :: `Bytes bytes :: tl ->
        `Coefficient_b (atoz_bigendian bytes) :: parse tl
    | `Type (_, (`BASE_POINT_G, _)) :: `Length _ :: `Bytes bytes :: tl ->
        `Base_point_g (atoz_bigendian bytes) :: parse tl
    | `Type (_, (`BASE_POINT_R_ORDER, _)) :: `Length _ :: `Bytes bytes :: tl ->
        `Base_point_r_order (atoz_bigendian bytes) :: parse tl
    | `Type (_, (`PUBLIC_POINT_Y, _)) :: `Length _ :: `Bytes bytes :: tl ->
        `Public_point_y (atoz_bigendian bytes) :: parse tl
    | `Type (_, (`COFACTOR_F, _)) :: `Length _ :: `Bytes bytes :: tl ->
        `Cofactor_f (atoz_bigendian bytes) :: parse tl
    | [] ->
        []
    | `Type (_, _) :: tl
    | `Length _ :: tl
    | `Bytes _ :: tl
    | `Value _ :: tl ->
        parse tl
  in
  let symbols = parse tokens in
  let oid =
    try
      let x = List.find (function `Oid x -> true | _ -> false) symbols in
      match x with
        | `Oid x ->
            Some x
        | _ -> None
    with Not_found -> None
  in
  let open Result in
  match oid with
    | Some (RSA _) ->
        begin match symbols with
          | [ `Oid _
            ; `Modulus n
            ; `Exponent e
            ] ->
              Ok (`RSA (n, e))
          | _ ->
              Error "Parse error: some elements are missing or are not correctly sorted"
        end
    | Some (ECDSA _) ->
          begin match symbols with
            | [ `Oid _
              ; `Modulus modulus
              ; `Exponent (* `Coefficient_a *) coefficient_a
              ; `Coefficient_b coefficient_b
              ; `Base_point_g base_point_g
              ; `Base_point_r_order base_point_r_order
              ; `Public_point_y public_point_y
              ; `Cofactor_f cofactor_f
              ] ->
                Ok (
                  `ECDSA
                    ( modulus
                    , coefficient_a
                    , coefficient_b
                    , base_point_g
                    , base_point_r_order
                    , public_point_y
                    , cofactor_f
                    ))
            | _ ->
                Error "Parse error: some elements are missing or are not correctly sorted"
          end
    | Some (Unknown oid) ->
        Error (Printf.sprintf "unknown OID \"%s\"." (Asn.OID.to_string oid))
    | None ->
        Error "invalid CVC key: OID not found"

module RSA =
struct
  module Public =
  struct
    type t = {
      n: Z.t;
      e: Z.t;
    }
    [@@deriving ord,yojson,eq,show]

    let decode bytes =
      let open Result in
      match decode bytes with
        | Ok (`RSA (n, e)) ->
            Ok {n; e}
        | Ok (`ECDSA _)
        | Ok `UNKNOWN ->
            Error "CVC: Algorithm OID and parameters do not match."
        | Error _ as err ->
            err
  end
end

module EC =
struct
  module Public =
  struct
    type t =
      { modulus : Z.t
      ; coefficient_a : Z.t
      ; coefficient_b : Z.t
      ; base_point_g : Z.t
      ; base_point_r_order : Z.t
      ; public_point_y : Z.t
      ; cofactor_f : Z.t
      }
      [@@deriving ord,yojson,eq,show]

    let decode bytes =
      let open Result in
      match decode bytes with
        | Ok(
            `ECDSA(
              modulus
              , coefficient_a
              , coefficient_b
              , base_point_g
              , base_point_r_order
              , public_point_y
              , cofactor_f)) ->
            Ok
              { modulus
              ; coefficient_a
              ; coefficient_b
              ; base_point_g
              ; base_point_r_order
              ; public_point_y
              ; cofactor_f
              }
        | Ok (`RSA _)
        | Ok `UNKNOWN ->
            Error "CVC: Algorithm OID and parameters do not match."
        | Error _ as err ->
            err
  end
end
