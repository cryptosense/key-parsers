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

module Cstruct = struct
  include Cstruct

  let to_hex_string cs =
    let buf = Buffer.create 0 in
    hexdump_to_buffer buf cs;
    Buffer.contents buf

  let pp = pp_of_to_string to_hex_string

  let to_yojson cs =
    `String (to_string cs)

  let of_yojson = function
    | `String s -> Result.Ok (of_string s)
    | _ -> Result.Error "Cannot convert this json value to Cstruct.t"
end

module RSA =
struct
  module Params =
  struct
    type t = unit
    let grammar = Asn.null
  end

  module Public =
  struct
    type t = {
      n: Z.t;
      e: Z.t;
    }
    [@@deriving ord,yojson]

    let grammar =
      let open Asn in
      let f (n, e) = { n; e } in
      let g { n; e } = (n, e) in
      map f g @@ sequence2
        (required ~label:"modulus" integer)
        (required ~label:"publicExponent" integer)

    let encode = Asn.(encode (codec der grammar))

    let decode key =
      let open Asn in
      try_with_asn @@ fun () ->
      let t, left = decode_exn (codec ber grammar) key in
      if Cstruct.len left = 0 then t
      else parse_error "PKCS1: RSA public key with non empty leftover"
  end

  module Private =
  struct
    type other_prime = {
      r: Z.t;
      d: Z.t;
      t: Z.t;
    }
    [@@deriving ord,yojson]

    let other_prime_grammar =
      let open Asn in
      let f (r, d, t) = { r; d; t } in
      let g { r; d; t } = (r, d, t) in
      map f g @@ sequence3
        (required ~label:"prime" integer)
        (required ~label:"exponent" integer)
        (required ~label:"coefficient" integer)

    type t = {
      n: Z.t;
      e: Z.t;
      d: Z.t;
      p: Z.t;
      q: Z.t;
      dp: Z.t;
      dq: Z.t;
      qinv: Z.t;
      other_primes: other_prime list;
    }
    [@@deriving ord,yojson]

    let grammar =
      let open Asn in
      let f = function
        | (0, (n, (e, (d, (p, (q, (dp, (dq, (qinv, None))))))))) ->
            { n; e; d; p; q; dp; dq; qinv; other_primes=[]; }
        | (1, (n, (e, (d, (p, (q, (dp, (dq, (qinv, Some other_primes))))))))) ->
            { n; e; d; p; q; dp; dq; qinv; other_primes; }
        | _ ->
            parse_error
              "PKCS#1: RSA private key version inconsistent with key data" in
      let g { n; e; d; p; q; dp; dq; qinv; other_primes } =
        (0, (n, (e, (d, (p, (q ,(dp ,(dq, (qinv, None))))))))) in
      map f g @@ sequence
      @@ (required ~label:"version" int)
         @ (required ~label:"modulus" integer)
         @ (required ~label:"publicExponent" integer)
         @ (required ~label:"privateExponent" integer)
         @ (required ~label:"prime1" integer)
         @ (required ~label:"prime2" integer)
         @ (required ~label:"exponent1" integer)
         @ (required ~label:"exponent2" integer)
         @ (required ~label:"coefficient" integer)
           -@ (optional ~label:"otherPrimeInfo" (sequence_of other_prime_grammar))

    let encode = Asn.(encode (codec der grammar))

    let decode key =
      let open Asn in
      try_with_asn @@ fun () ->
      let t, left = decode_exn (codec ber grammar) key in
      if Cstruct.len left = 0 then t
      else parse_error "PKCS1: RSA private key with non empty leftover"
  end
end

module RSA_CVC =
struct
  module Params =
  struct
    type t = unit
    let grammar = Asn.null
  end

  module Public =
  struct
    type t = {
      n: Z.t;
      e: Z.t;
    }
    [@@deriving ord,yojson]

    let grammar =
      let open Asn in
      let f (n, e) = { n; e } in
      let g { n; e } = (n, e) in
      map f g @@ sequence2
        (required ~label:"modulus" integer)
        (required ~label:"publicExponent" integer)

    let encode = Asn.(encode (codec der grammar))

    let decode key =
      let open Asn in
      try_with_asn @@ fun () ->
      let t, left = decode_exn (codec ber grammar) key in
      if Cstruct.len left = 0 then t
      else parse_error "PKCS1: RSA public key with non empty leftover"
  end
end

module ECDSA_CVC =
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
      [@@deriving ord,yojson]
  end
end

module DSA =
struct
  module Params =
  struct
    type t = {
      p: Z.t;
      q: Z.t;
      g: Z.t;
    }
    [@@deriving ord,yojson]

    let grammar =
      let open Asn in
      let f (p, q, g) = { p; q; g } in
      let g { p; q; g } = (p, q, g) in
      map f g @@ sequence3
        (required ~label:"p" integer)
        (required ~label:"q" integer)
        (required ~label:"g" integer)

    let encode = Asn.(encode (codec der grammar))

    let decode key =
      let open Asn in
      try_with_asn @@ fun () ->
      let t, left = decode_exn (codec ber grammar) key in
      if Cstruct.len left = 0 then t
      else parse_error "DSA: Params with non empty leftover"
  end

  module Public =
  struct
    type t = Z.t
    [@@deriving ord,yojson]

    let grammar = Asn.integer

    let encode = Asn.(encode (codec der grammar))

    let decode key =
      let open Asn in
      try_with_asn @@ fun () ->
      let t, left = decode_exn (codec ber grammar) key in
      if Cstruct.len left = 0 then t
      else parse_error "DSA: public key with non empty leftover"
  end

  module Private =
  struct
    type t = Z.t
    [@@deriving ord,yojson]

    let grammar = Asn.integer

    let encode = Asn.(encode (codec der grammar))

    let decode key =
      let open Asn in
      try_with_asn @@ fun () ->
      let t, left = decode_exn (codec ber grammar) key in
      if Cstruct.len left = 0 then t
      else parse_error "DSA: private key with non empty leftover"
  end
end

module EC =
struct
  type point = Cstruct.t
  [@@deriving ord,show,yojson]

  let point_grammar = Asn.octet_string

  module Field =
  struct
    let prime_oid = Asn.OID.of_string "1.2.840.10045.1.1"
    let characteristic_two_oid = Asn.OID.of_string "1.2.840.10045.1.2"

    let gn_oid = Asn.OID.(characteristic_two_oid <| 3 <| 1)
    let tp_oid = Asn.OID.(characteristic_two_oid <| 3 <| 2)
    let pp_oid = Asn.OID.(characteristic_two_oid <| 3 <| 3)

    type basis_type = | GN_typ | TP_typ | PP_typ
    let basis_type_grammar =
      let open Asn in
      let f = function
        | oid when oid = gn_oid -> GN_typ
        | oid when oid = tp_oid -> TP_typ
        | oid when oid = pp_oid -> PP_typ
        | _ -> parse_error "EC: unexpected basis type OID" in
      let g = function
        | GN_typ -> gn_oid
        | TP_typ -> tp_oid
        | PP_typ -> pp_oid in
      map f g oid

    type basis =
      | GN
      | TP of Z.t
      | PP of Z.t * Z.t * Z.t
    [@@deriving ord,show,yojson]

    let basis_grammar =
      let open Asn in
      let f = function
        | `C1 () -> GN
        | `C2 k -> TP k
        | `C3 (k1, k2, k3) -> PP (k1, k2, k3) in
      let g = function
        | GN -> `C1 ()
        | TP k -> `C2 k
        | PP (k1, k2, k3) -> `C3 (k1, k2, k3) in
      map f g @@ choice3
        null
        integer
        (sequence3
           (required ~label:"k1" integer)
           (required ~label:"k2" integer)
           (required ~label:"k3" integer))

    type characteristic_two_params = {
      m: Z.t;
      basis: basis;
    }
    [@@deriving ord,show,yojson]

    let ctwo_params_grammar =
      let open Asn in
      let f = function
        | (m, GN_typ, GN) -> { m; basis=GN }
        | (m, TP_typ, TP k) -> { m; basis=TP k }
        | (m, PP_typ, PP (k1, k2, k3)) -> { m; basis=PP (k1, k2, k3) }
        | _ -> parse_error "EC: field basis type and parameters don't match" in
      let g { m; basis } =
        match basis with
          | GN -> (m, GN_typ, GN)
          | TP k -> (m, TP_typ, TP k)
          | PP (k1, k2, k3) -> (m, PP_typ, PP (k1, k2, k3)) in
      map f g @@ sequence3
        (required ~label:"m" integer)
        (required ~label:"basis" basis_type_grammar)
        (required ~label:"parameters" basis_grammar)

    type typ =
      | Prime_typ
      | C_two_typ

    let typ_grammar =
      let open Asn in
      let f = function
        | oid when oid = prime_oid -> Prime_typ
        | oid when oid = characteristic_two_oid -> C_two_typ
        | _ -> parse_error "EC: unexpected field type OID" in
      let g = function
        | Prime_typ -> prime_oid
        | C_two_typ -> characteristic_two_oid in
      map f g oid

    type parameters =
      | Prime_p of Z.t
      | C_two_p of characteristic_two_params

    let parameters_grammar =
      let open Asn in
      let f = function
        | `C1 p -> Prime_p p
        | `C2 params -> C_two_p params in
      let g = function
        | Prime_p p -> `C1 p
        | C_two_p params -> `C2 params in
      map f g @@ choice2
        integer
        ctwo_params_grammar

    type t =
      | Prime of Z.t
      | C_two of characteristic_two_params
    [@@deriving ord,show,yojson]

    let grammar =
      let open Asn in
      let f = function
        | Prime_typ, Prime_p p -> Prime p
        | C_two_typ, C_two_p params -> C_two params
        | _ -> parse_error "EC: field type and parameters don't match" in
      let g = function
        | Prime p -> Prime_typ, Prime_p p
        | C_two params -> C_two_typ, C_two_p params in
      map f g @@ sequence2
        (required ~label:"fieldType" typ_grammar)
        (required ~label:"parameters" parameters_grammar)
  end

  module Specified_domain =
  struct
    type field_element = Cstruct.t
    [@@deriving ord,show,yojson]

    let field_element_grammar = Asn.octet_string

    type curve = {
      a: field_element;
      b: field_element;
      seed: Cstruct.t option;
    }
    [@@deriving ord,show,yojson]

    let curve_grammar =
      let open Asn in
      let f (a, b, seed) = { a; b; seed } in
      let g {a; b; seed } = (a, b, seed) in
      map f g @@
      sequence3
        (required ~label:"a" field_element_grammar)
        (required ~label:"b" field_element_grammar)
        (optional ~label:"seed" bit_string_cs)

    type t = {
      field: Field.t;
      curve: curve;
      base: point;
      order: Z.t;
      cofactor: Z.t option;
    }
    [@@deriving ord,show,yojson]

    let grammar =
      let open Asn in
      let f (version, field, curve, base, order , cofactor) =
        if version = 1 then { field; curve; base; order; cofactor }
        else parse_error "EC: Unknown ECParameters version" in
      let g { field; curve; base; order; cofactor } =
        (1, field, curve, base, order, cofactor) in
      map f g @@ sequence6
        (required ~label:"version" int)
        (required ~label:"fieldID" Field.grammar)
        (required ~label:"curve" curve_grammar)
        (required ~label:"base" point_grammar)
        (required ~label:"order" integer)
        (optional ~label:"cofactor" integer)
  end

  module Params =
  struct
    type t =
      | Named of Asn.OID.t
      | Implicit
      | Specified of Specified_domain.t
    [@@deriving ord,show,yojson]

    let grammar =
      let open Asn in
      let f = function
        | `C1 oid -> Named oid
        | `C2 () -> Implicit
        | `C3 domain -> Specified domain in
      let g = function
        | Named oid -> `C1 oid
        | Implicit -> `C2 ()
        | Specified domain -> `C3 domain in
      map f g @@ choice3
        oid
        null
        Specified_domain.grammar

    let encode = Asn.(encode (codec der grammar))
    let decode params =
      let open Asn in
      try_with_asn @@ fun () ->
      let t, left = decode_exn (codec ber grammar) params in
      if Cstruct.len left = 0 then t
      else parse_error "EC: parameters with non empty leftover"
  end

  module Public =
  struct
    type t = point
    [@@deriving ord,show,yojson]

    let grammar = point_grammar

    let encode = Asn.(encode (codec der grammar))
    let decode key =
      let open Asn in
      try_with_asn @@ fun () ->
      let t, left = decode_exn (codec ber grammar) key in
      if Cstruct.len left = 0 then t
      else parse_error "EC: public key with non empty leftover"
  end

  module Private =
  struct
    type t = {
      k: Cstruct.t;
      params: Params.t option;
      public_key: Public.t option;
    }
    [@@deriving ord,show,yojson]

    let grammar =
      let open Asn in
      let f (version, k, params, public_key) =
        if version = 1 then { k; params; public_key }
        else parse_error "EC: unknown private key version" in
      let g { k; params; public_key } =
        (1, k, params, public_key) in
      map f g @@ sequence4
        (required ~label:"version" int)
        (required ~label:"privateKey" octet_string)
        (optional ~label:"ECParameters" @@ explicit 0 Params.grammar)
        (optional ~label:"publicKey" @@ explicit 1 bit_string_cs)

    let encode = Asn.(encode (codec der grammar))
    let decode key =
      let open Asn in
      try_with_asn @@ fun () ->
      let t, left = decode_exn (codec ber grammar) key in
      if Cstruct.len left = 0 then t
      else parse_error "EC: private key with non empty leftover"
  end
end

module DH =
struct
  module Params =
  struct
    type t = {
      p: Z.t;
      g: Z.t;
      l: Z.t option; (* privateValueLength *)
    }
    [@@deriving ord,yojson]

    let grammar =
      let open Asn in
      let to_struct (p, g, l) = { p; g; l } in
      let of_struct {p; g; l} = ( p, g, l ) in
      map to_struct of_struct @@ sequence3
        (required ~label:"p" integer)
        (required ~label:"g" integer)
        (optional ~label:"l" integer)

    let encode = Asn.(encode (codec der grammar))

    let decode key =
      let open Asn in
      try_with_asn @@ fun () ->
      let t, left = decode_exn (codec ber grammar) key in
      if Cstruct.len left = 0 then t
      else parse_error "DH: Params with non empty leftover"
  end

  module Public =
  struct
    type t = Z.t
    [@@deriving ord,yojson]

    let grammar = Asn.integer

    let encode = Asn.(encode (codec der grammar))

    let decode key =
      let open Asn in
      try_with_asn @@ fun () ->
      let t, left = decode_exn (codec ber grammar) key in
      if Cstruct.len left = 0 then t
      else parse_error "DH: public key with non empty leftover"
  end

  module Private =
  struct
    type t = Z.t
    [@@deriving ord,yojson]

    let grammar = Asn.integer

    let encode = Asn.(encode (codec der grammar))

    let decode key =
      let open Asn in
      try_with_asn @@ fun () ->
      let t, left = decode_exn (codec ber grammar) key in
      if Cstruct.len left = 0 then t
      else parse_error "DH: private key with non empty leftover"
  end
end

module Algorithm_identifier =
struct
  module Algo =
  struct
    let rsa_oid = Asn.OID.of_string "1.2.840.113549.1.1.1"
    let dsa_oid = Asn.OID.of_string "1.2.840.10040.4.1"
    let ec_oid = Asn.OID.of_string "1.2.840.10045.2.1"
    let dh_oid = Asn.OID.of_string "1.2.840.113549.1.3.1"

    let ec_dh = Asn.OID.of_string "1.3.132.1.12"
    let ec_mqv = Asn.OID.of_string "1.3.132.1.13"

    type t =
      | DSA
      | RSA
      | EC
      | DH
      | Unknown of Asn.OID.t

    let grammar =
      let open Asn in
      let f = function
        | oid when oid = rsa_oid -> RSA
        | oid when oid = dsa_oid -> DSA
        | oid when oid = ec_oid
                || oid = ec_dh
                || oid = ec_mqv -> EC
        | oid when oid = dh_oid -> DH
        | oid -> Unknown oid in
      let g = function
        | RSA -> rsa_oid
        | DSA -> dsa_oid
        | EC -> ec_oid
        | DH -> dh_oid
        | Unknown oid -> oid in
      map f g oid
  end

  let rsa_grammar =
    let open Asn in
    let f = function
      | Algo.RSA, () -> ()
      | _ -> parse_error "Algorithm OID and parameters don't match" in
    let g () = Algo.RSA, () in
    map f g @@ sequence2
      (required ~label:"algorithm" Algo.grammar)
      (required ~label:"parameters" RSA.Params.grammar)

  let dsa_grammar =
    let open Asn in
    let f = function
      | Algo.DSA, params -> params
      | _, _ -> parse_error "Algorithm OID and parameters don't match" in
    let g params = Algo.DSA, params in
    map f g @@ sequence2
      (required ~label:"algorithm" Algo.grammar)
      (required ~label:"parameters" DSA.Params.grammar)

  let ec_grammar =
    let open Asn in
    let f = function
      | Algo.EC, params -> params
      | _, _ -> parse_error "Algorithm OID and parameters don't match" in
    let g params = Algo.EC, params in
    map f g @@ sequence2
      (required ~label:"algorithm" Algo.grammar)
      (required ~label:"parameters" EC.Params.grammar)

  let dh_grammar =
    let open Asn in
    let f = function
      | Algo.DH, params -> params
      | _, _ -> parse_error "Algorithm OID and parameters don't match" in
    let g params = Algo.DH, params in
    map f g @@ sequence2
      (required ~label:"algorithm" Algo.grammar)
      (required ~label:"parameters" DH.Params.grammar)

end

let map_result f = function Result.Ok x -> Result.Ok (f x) | Result.Error _ as r -> r
let default_result default = function Result.Error _ -> default () | Result.Ok _ as r -> r

module CVC = struct
  let rsa_oid = Asn.OID.of_string "0.4.0.127.0.7.2.2.2.1.4"
  let ecdsa_oid = Asn.OID.of_string "0.4.0.127.0.7.2.2.2.2.3"

  type t =
    [ `RSA of RSA_CVC.Public.t | `ECDSA of ECDSA_CVC.Public.t | `UNKNOWN ]

  type algo_typ =
    | RSA
    | ECDSA
    | Unknown of Asn.OID.t

  type parser_state =
    | Init
    | Type
    | Length
    | Value of int

  let cvc_object_types =
    [ 0x7F21, (`CV_CERTIFICATE, true)
    ; 0x7F4E, (`CERTIFICATE_BODY, true)
    ; 0x5F29, (`PROFILE_IDENTIFIER, false)
    ; 0x7F49, (`PUBLIC_KEY, true)
    ; 0x5F20, (`HOLDER_REFERENCE, false)
    ; 0x7F4C, (`HOLDER_AUTH_TEMPLATE, true)
    ; 0x5F25, (`EFFECTIVE_DATE, false)
    ; 0x5F24, (`EXPIRATION_DATE, false)
    ; 0x5F37, (`SIGNATURE, false)
    ; 0x06, (`OID, false)
    ; 0x42, (`CA_REFERENCE, false)
    ; 0x67, (`REQ_AUTHENTICATION, true)
    ; 0x53, (`ROLE_AND_ACCESS_RIGHTS, false)
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
    let code =
      String.get tag 0
      |> Char.code
    in
    try code, List.assoc code cvc_object_types
    with Not_found ->
      let code =
        let msb = code * 0x100 in
        let lsb =
          String.get tag 1
          |> Char.code
        in
        msb + lsb
      in
      code, List.assoc code cvc_object_types

  let atoi_bigendian s =
    let rec aux acc i =
      if i >= String.length s then acc
      else
        let acc = Char.code (String.get s i) + (acc * 0x100) in
        aux acc (i + 1)
    in aux 0 0

  (* because this function allocations a new buffer, it is not very memory efficient.
   * Should reverse the string in-place, or find a better way to do this. *)
  let atoz_bigendian s =
    let bytes = Bytes.of_string s in
    let s = Bytes.make (Bytes.length bytes) '\000' in
    let () =
      for i = 0 to Bytes.length bytes - 1 do
        let ilast = Bytes.length bytes - (1 + i) in
        Bytes.set s i (Bytes.get bytes ilast);
      done;
    in
    let s = Bytes.to_string s in
    Z.of_bits s

  let grammar =
    let open Asn in
    let f = function
      | oid when oid = rsa_oid -> RSA
      | oid when oid = ecdsa_oid -> ECDSA
      | oid -> Unknown oid in
    let g = function
      | RSA -> rsa_oid
      | ECDSA -> ecdsa_oid
      | Unknown oid -> oid in
    map f g oid

  let decode_oid str =
    let t, left = Asn.(decode_exn (codec ber grammar) str) in
    t

  let decode bytes =
    let open Result in
    let buffer = Bytes.make 4096 '\000' in
    (* it's been a while since I took a class which covered FSM's, so this is not ideal.
     * I should probably rewrite this with an accumulator parameter, so that it can take
     * advantage of tailcall optimization and eliminate that part of the memory waste.
     *)
    let rec tokenize bytes i state = function
      | Init ->
          if String.length bytes <= i then raise (Failure "Trying to tokenize an empty string")
          else tokenize bytes i None Type
      | Type ->
          String.blit bytes i buffer 0 2;
          let cvc_type = find_cvc_object_type (Bytes.to_string buffer) in
          begin match cvc_type with
            | tag, _ when tag <= 0xff ->
                let i = i + 1 in
                (`Type cvc_type) :: tokenize bytes i (Some cvc_type) Length
            | tag, _ when tag > 0xff ->
                let i = i + 2 in
                (`Type cvc_type) :: tokenize bytes i (Some cvc_type) Length
          end
      | Length ->
          let code = Char.code (String.get bytes i) in
          if code < 0x80
          then begin
            let i = i + 1 in
            (`Length code) :: tokenize bytes i state (Value code)
          end
          else
            begin match code with
              | 0x81 ->
                  let code = Char.code (String.get bytes (i + 1)) in
                  let i = i + 2 in
                  (`Length code) :: tokenize bytes i state (Value code)
              | 0x82 ->
                  let code =
                    let msb = Char.code (String.get bytes (i + 1)) * 0x100 in
                    let lsb = Char.code (String.get bytes (i + 2)) in
                    msb + lsb
                  in
                  let i = i + 3 in
                  (`Length code) :: tokenize bytes i state (Value code)
              | _ ->
                  raise (Failure "Invalid LENGTH field in TLV encoded CVC data")
            end
      | Value length ->
          let is_rec =
            match state with
              | None -> false
              | Some (_, (_, x)) -> x
          in
          let bytes' =
            String.sub bytes i length
          in
          let v =
            if is_rec
            then
              `Value (tokenize bytes' 0 None Init)
            else `Bytes bytes'
          in
          v :: (if length + i >= String.length bytes then [] else tokenize bytes (i + length) None Init)
    in
    let tokens = tokenize (Cstruct.to_string bytes) 0 None Init in
    let rec parse = function
      | `Type (_, (`PUBLIC_KEY, _)) :: `Length _ :: `Value ls :: _ ->
          parse ls
      | `Type (_, (`OID, _)) :: `Length _ :: `Bytes bytes :: tl ->
          let bytes = Printf.sprintf "\006%c%s" (Char.chr (String.length bytes)) bytes in
          `Oid (decode_oid (Cstruct.of_string bytes)) :: parse tl
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
      | _ ->
          raise (Failure "unaccounted for case")
    in
    let symbols = parse tokens in
    let oid = List.find (function `Oid x -> true | _ -> false) symbols in
    match oid with
      | `Oid RSA ->
          `RSA
            RSA_CVC.Public.(
              let n =
                List.fold_left (fun acc x -> (match x with `Modulus x -> [x] | _ -> []) @ acc) [] symbols
                |> List.hd
              in
              let e =
                List.fold_left (fun acc x -> (match x with `Exponent x -> [x] | _ -> []) @ acc) [] symbols
                |> List.hd
              in
              {n; e})
      | `Oid ECDSA ->
          `ECDSA
            ECDSA_CVC.Public.(
              let modulus =
                List.fold_left (fun acc x -> (match x with `Modulus x -> [x] | _ -> []) @ acc) [] symbols
                |> List.hd
              in
              let coefficient_a =
                List.fold_left (fun acc x -> (match x with `Coefficient_a x | `Exponent x -> [x] | _ -> []) @ acc) [] symbols
                |> List.hd
              in
              let coefficient_b =
                List.fold_left (fun acc x -> (match x with `Coefficient_b x -> [x] | _ -> []) @ acc) [] symbols
                |> List.hd
              in
              let base_point_g =
                List.fold_left (fun acc x -> (match x with `Base_point_g x -> [x] | _ -> []) @ acc) [] symbols
                |> List.hd
              in
              let base_point_r_order =
                List.fold_left (fun acc x -> (match x with `Base_point_r_order x -> [x] | _ -> []) @ acc) [] symbols
                |> List.hd
              in
              let public_point_y =
                List.fold_left (fun acc x -> (match x with `Public_point_y x -> [x] | _ -> []) @ acc) [] symbols
                |> List.hd
              in
              let cofactor_f =
                List.fold_left (fun acc x -> (match x with `Cofactor_f x -> [x] | _ -> []) @ acc) [] symbols
                |> List.hd
              in
              { modulus; coefficient_a; coefficient_b; base_point_g; base_point_r_order; public_point_y; cofactor_f
              }
            )
      | `Oid (Unknown _) -> `UNKNOWN

end

module X509 =
struct
  type t =
    [ `RSA of RSA.Public.t
    | `DSA of DSA.Params.t * DSA.Public.t
    | `EC of EC.Params.t * EC.Public.t
    | `DH of DH.Params.t * DH.Public.t
    ]
  [@@deriving ord,yojson]

  let rsa_grammar =
    let open Asn in
    let f ((), bit_string) = raise_asn @@ fun () -> RSA.Public.decode bit_string in
    let g key = (), RSA.Public.encode key in
    map f g @@ sequence2
      (required ~label:"alogrithm" Algorithm_identifier.rsa_grammar)
      (required ~label:"subjectPublicKey" bit_string_cs)

  let dsa_grammar =
    let open Asn in
    let f (params, bit_string) = params, raise_asn @@ fun () -> DSA.Public.decode bit_string in
    let g (params, key) = params, DSA.Public.encode key in
    map f g @@ sequence2
      (required ~label:"alogrithm" Algorithm_identifier.dsa_grammar)
      (required ~label:"subjectPublicKey" bit_string_cs)

  let ec_grammar =
    let open Asn in
    let f (params, bit_string) = params, bit_string in
    let g (params, key) = params, key in
    map f g @@ sequence2
      (required ~label:"alogrithm" Algorithm_identifier.ec_grammar)
      (required ~label:"subjectPublicKey" bit_string_cs)

  let dh_grammar =
    let open Asn in
    let f (params, bit_string) = params, raise_asn @@ fun () -> DH.Public.decode bit_string in
    let g (params, key) = params, DH.Public.encode key in
    map f g @@ sequence2
      (required ~label:"algorithm" Algorithm_identifier.dh_grammar)
      (required ~label:"subjectPublicKey" bit_string_cs)

  let encode_rsa = Asn.(encode (codec der rsa_grammar))
  let encode_dsa = Asn.(encode (codec der dsa_grammar))
  let encode_ec = Asn.(encode (codec der ec_grammar))
  let encode_dh = Asn.(encode (codec der dh_grammar))

  let encode = function
    | `RSA key -> encode_rsa key
    | `DSA key -> encode_dsa key
    | `EC key -> encode_ec key
    | `DH key -> encode_dh key

  let decode_rsa key =
    let open Asn in
    try_with_asn @@ fun () ->
    let t, left = decode_exn (codec ber rsa_grammar) key in
    if Cstruct.len left = 0 then t
    else parse_error "X509: key with non empty leftover"

  let decode_dsa key =
    let open Asn in
    try_with_asn @@ fun () ->
    let t, left = decode_exn (codec ber dsa_grammar) key in
    if Cstruct.len left = 0 then t
    else parse_error "X509: key with non empty leftover"

  let decode_ec key =
    let open Asn in
    try_with_asn @@ fun () ->
    let t, left = decode_exn (codec ber ec_grammar) key in
    if Cstruct.len left = 0 then t
    else parse_error "X509: key with non empty leftover"

  let decode_dh key =
    let open Asn in
    try_with_asn @@ fun () ->
    let t, left = decode_exn (codec ber dh_grammar) key in
    if Cstruct.len left = 0 then t
    else parse_error "X509: key with non empty leftover"

  let decode key : (t, string) Result.result =
    (map_result (fun x -> `RSA x) (decode_rsa key))
    |> default_result (fun () -> map_result (fun x -> `DSA x) (decode_dsa key))
    |> default_result (fun () -> map_result (fun x -> `EC x) (decode_ec key))
    |> default_result (fun () -> map_result (fun x -> `DH x) (decode_dh key))
    |> default_result @@ fun () -> Result.Error "Couldn't parse key"
end

module PKCS8 =
struct
  type t =
    [ `RSA of RSA.Private.t
    | `DSA of DSA.Params.t * DSA.Private.t
    | `EC of EC.Params.t * EC.Private.t
    | `DH of DH.Params.t * DH.Private.t
    ]
  [@@deriving ord,yojson]

  let rsa_grammar =
    let open Asn in
    let f (version, (), octet_string, attributes) =
      if version = 0 then
        raise_asn @@ fun () -> RSA.Private.decode octet_string
      else
        parse_error @@ Printf.sprintf "PKCS8: version %d not supported" version in
    let g key = 0, (), RSA.Private.encode key, None in
    map f g @@ sequence4
      (required ~label:"version" int)
      (required ~label:"privateKeyAlogrithm" Algorithm_identifier.rsa_grammar)
      (required ~label:"privateKey" octet_string)
      (optional ~label:"attributes" @@ implicit 0 null)

  let dsa_grammar =
    let open Asn in
    let f (version, params, octet_string, attributes) =
      if version = 0 then
        params, raise_asn @@ fun () -> DSA.Private.decode octet_string
      else
        parse_error @@ Printf.sprintf "PKCS8: version %d not supported" version in
    let g (params, key) = 0, params, DSA.Private.encode key, None in
    map f g @@ sequence4
      (required ~label:"version" int)
      (required ~label:"privateKeyAlogrithm" Algorithm_identifier.dsa_grammar)
      (required ~label:"privateKey" octet_string)
      (optional ~label:"attributes" @@ implicit 0 null)

  let ec_grammar =
    let open Asn in
    let f (version, params, octet_string, attributes) =
      if version = 0 then
        params, raise_asn @@ fun () -> EC.Private.decode octet_string
      else
        parse_error @@ Printf.sprintf "PKCS8: version %d not supported" version in
    let g (params, key) = 0, params, EC.Private.encode key, None in
    map f g @@ sequence4
      (required ~label:"version" int)
      (required ~label:"privateKeyAlogrithm" Algorithm_identifier.ec_grammar)
      (required ~label:"privateKey" octet_string)
      (optional ~label:"attributes" @@ implicit 0 null)

  let dh_grammar =
    let open Asn in
    let f (version, params, octet_string, attributes) =
      if version = 0 then
        params, raise_asn @@ fun () -> DH.Private.decode octet_string
      else
        parse_error @@ Printf.sprintf "PKCS8: version %d not supported" version in
    let g (params, key) = 0, params, DH.Private.encode key, None in
    map f g @@ sequence4
      (required ~label:"version" int)
      (required ~label:"privateKeyAlogrithm" Algorithm_identifier.dh_grammar)
      (required ~label:"privateKey" octet_string)
      (optional ~label:"attributes" @@ implicit 0 null)

  let encode_rsa = Asn.(encode (codec der rsa_grammar))
  let encode_dsa = Asn.(encode (codec der dsa_grammar))
  let encode_ec = Asn.(encode (codec der ec_grammar))
  let encode_dh = Asn.(encode (codec der dh_grammar))

  let encode = function
    | `RSA key -> encode_rsa key
    | `DSA key -> encode_dsa key
    | `EC key -> encode_ec key
    | `DH key -> encode_dh key

  let decode_rsa key =
    let open Asn in
    try_with_asn @@ fun () ->
    let t, left = decode_exn (codec ber rsa_grammar) key in
    if Cstruct.len left = 0 then t
    else parse_error "PKCS8: key with non empty leftover"

  let decode_dsa key =
    let open Asn in
    try_with_asn @@ fun () ->
    let t, left = decode_exn (codec ber dsa_grammar) key in
    if Cstruct.len left = 0 then t
    else parse_error "PKCS8: key with non empty leftover"

  let decode_ec key =
    let open Asn in
    try_with_asn @@ fun () ->
    let t, left = decode_exn (codec ber ec_grammar) key in
    if Cstruct.len left = 0 then t
    else parse_error "PKCS8: key with non empty leftover"

  let decode_dh key =
    let open Asn in
    try_with_asn @@ fun () ->
    let t, left = decode_exn (codec ber dh_grammar) key in
    if Cstruct.len left = 0 then t
    else parse_error "PKCS8: key with non empty leftover"

  let decode key : (t, string) Result.result =
    (map_result (fun x -> `RSA x) (decode_rsa key))
    |> default_result (fun () -> map_result (fun x -> `DSA x) (decode_dsa key))
    |> default_result (fun () -> map_result (fun x -> `EC x) (decode_ec key))
    |> default_result (fun () -> map_result (fun x -> `DH x) (decode_dh key))
    |> default_result @@ fun () -> Result.Error "Couldn't parse key"
end
