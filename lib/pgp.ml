(*exception Subpacket of string

  exception Signature of string*)

let ( >>= ) = Result.bind

let ( >|= ) result f = Result.map f result

type error_type =
  | Fatal
  | Header of int * int64

(*from ltpa.ml*)

let get_z_be cs off len =
  let r = ref Z.zero in
  let base = Z.of_int 0x100 in
  for i = off to off + len - 1 do
    r := Z.add (Z.mul base !r) @@ Z.of_int @@ Cstruct.get_uint8 cs i
  done;
  !r

(***)

let decode_mpi cs off =
  let bit_length = Cstruct.BE.get_uint16 cs off in
  let length = (bit_length / 8) + min 1 (bit_length mod 8) in
  (length, get_z_be cs (2 + off) length)

let decode_mpi_shift cs off =
  let bit_length = Cstruct.BE.get_uint16 cs off in
  let length = (bit_length / 8) + min 1 (bit_length mod 8) in
  let shifted_cs = Cstruct.shift cs (length + 2) in
  (shifted_cs, get_z_be cs (2 + off) length)

module Algo = struct
  module Public = struct
    type t =
      | Rsa_enc_sign
      | Rsa_enc_only
      | Rsa_sign_only
      | Elgamal_sign_only
      | Dsa
      | Ec
      | Ecdsa
      | Unknown
    [@@deriving ord, eq, show]

    let detag tag =
      match tag with
      | 1 -> Rsa_enc_sign
      | 2 -> Rsa_enc_only
      | 3 -> Rsa_sign_only
      | 16 -> Elgamal_sign_only
      | 17 -> Dsa
      | 18 -> Ec
      | 19 -> Ecdsa
      | _ -> Unknown

    let name algo =
      match algo with
      | Rsa_enc_sign -> "RSA Encryption & Signature"
      | Rsa_enc_only -> "RSA Encryption only"
      | Rsa_sign_only -> "RSA Signature only"
      | Elgamal_sign_only -> "Elgamal Signature only"
      | Dsa -> "DSA"
      | Ec -> "EC"
      | Ecdsa -> "ECDSA"
      | Unknown -> "Unknown public algorithm"
  end

  module Hash = struct
    type t =
      | Md5
      | Sha1
      | Ripe_md160
      | Sha2_256
      | Sha2_384
      | Sha2_512
      | Sha2_224
      | Sha3_256
      | Sha3_512
      | Unknown_hash_algo
    [@@deriving ord, eq, show]

    let detag tag =
      match tag with
      | 1 -> Md5
      | 2 -> Sha1
      | 3 -> Ripe_md160
      | 8 -> Sha2_256
      | 9 -> Sha2_384
      | 10 -> Sha2_512
      | 11 -> Sha2_224
      | 12 -> Sha3_256
      | 14 -> Sha3_512
      | _ -> Unknown_hash_algo

    let name algo =
      match algo with
      | Md5 -> "MD5"
      | Sha1 -> "SHA1"
      | Ripe_md160 -> "RIPE_MD160"
      | Sha2_256 -> "SHA2 256"
      | Sha2_384 -> "SHA2 384"
      | Sha2_512 -> "SHA2 512"
      | Sha2_224 -> "SHA2 224"
      | Sha3_256 -> "SHA3 256"
      | Sha3_512 -> "SHA3 512"
      | Unknown_hash_algo -> "Unknown hash algorithm"
  end

  module Symmetric = struct
    type t =
      | Plaintext
      | Idea
      | Triple_des
      | Cast_5
      | Blowfish
      | Aes_128
      | Aes_192
      | Aes_256
      | Twofish_256
      | Unknown

    let size algo =
      match algo with
      | Plaintext -> 0
      | Idea -> 8
      | Triple_des -> 8
      | Cast_5 -> 16
      | Blowfish -> 8
      | Aes_128 -> 16
      | Aes_192 -> 24
      | Aes_256 -> 32
      | Twofish_256 -> 32
      | Unknown -> 0

    let name algo =
      match algo with
      | Plaintext -> "Plain text"
      | Idea -> "IDEA"
      | Triple_des -> "Triple DES"
      | Cast_5 -> "Cast5"
      | Blowfish -> "Blowfish"
      | Aes_128 -> "AES 128"
      | Aes_192 -> "AES 192"
      | Aes_256 -> "AES 256"
      | Twofish_256 -> "Twofish 256"
      | Unknown -> "Unknown symmetric-key algorithm"

    let detag tag =
      match tag with
      | 0 -> Plaintext
      | 1 -> Idea
      | 2 -> Triple_des
      | 3 -> Cast_5
      | 4 -> Blowfish
      | 7 -> Aes_128
      | 8 -> Aes_192
      | 9 -> Aes_256
      | 10 -> Twofish_256
      | _ -> Unknown
  end
end

module Rsa = struct
  module Public = struct
    type t =
      { n : Derivable.Z.t
      ; e : Derivable.Z.t }
    [@@deriving ord, eq, show]

    let decode packet off =
      let (cs, n) = decode_mpi_shift packet off in
      let (shifted_cs, e) = decode_mpi_shift cs off in
      let public_key = {n; e} in
      (shifted_cs, public_key)
  end

  module Private = struct
    type t =
      { d : Derivable.Z.t
      ; p : Derivable.Z.t
      ; q : Derivable.Z.t
      ; u : Derivable.Z.t }
    [@@deriving ord, eq, show]

    let decode packet off =
      let (cs1, d) = decode_mpi_shift packet off in
      let (cs2, p) = decode_mpi_shift cs1 off in
      let (cs3, q) = decode_mpi_shift cs2 off in
      let (shifted_cs, u) = decode_mpi_shift cs3 off in
      print_newline ();
      (shifted_cs, {d; p; q; u})
  end

  module Signature = struct
    type t = Derivable.Z.t [@@deriving ord, eq, show]
  end
end

module Dsa = struct
  module Public = struct
    type t =
      { p : Derivable.Z.t
      ; q : Derivable.Z.t
      ; g : Derivable.Z.t
      ; y : Derivable.Z.t }
    [@@deriving ord, eq, show]

    let decode packet off =
      let (cs1, p) = decode_mpi_shift packet off in
      let (cs2, q) = decode_mpi_shift cs1 off in
      let (cs3, g) = decode_mpi_shift cs2 off in
      let (shifted_cs, y) = decode_mpi_shift cs3 off in
      (shifted_cs, {p; q; g; y})
  end

  module Private = struct
    type t = Derivable.Z.t [@@deriving ord, eq, show]

    let decode packet off = decode_mpi_shift packet off
  end

  module Signature = struct
    type t =
      { r : Derivable.Z.t
      ; s : Derivable.Z.t }
    [@@deriving ord, eq, show]
  end
end

module Elgamal = struct
  module Public = struct
    type t =
      { p : Derivable.Z.t
      ; g : Derivable.Z.t
      ; y : Derivable.Z.t }
    [@@deriving ord, eq, show]

    let decode packet off =
      let (cs1, p) = decode_mpi_shift packet off in
      let (cs2, g) = decode_mpi_shift cs1 off in
      let (shifted_cs, y) = decode_mpi_shift cs2 off in
      let public_key = {p; g; y} in
      (shifted_cs, public_key)
  end
  [@@deriving ord, eq, show]

  module Private = struct
    type t = Derivable.Z.t [@@deriving ord, eq, show]

    let decode packet off = decode_mpi_shift packet off
  end
end

module Packet = struct
  type packet_type =
    | Session_key
    | Signature
    | Secret_key
    | Public_key
    | Secret_subkey
    | Id
    | Public_subkey
    | Unknown_packet
  [@@deriving ord, eq, show]

  let detag tag =
    match tag with
    | 0 -> Error "Tag 0"
    | 1 -> Ok Session_key
    | 2 -> Ok Unknown_packet (*Signature*)
    | 5 -> Ok Secret_key
    | 6 -> Ok Public_key
    | 7 -> Ok Secret_subkey
    | 13 -> Ok Id
    | 14 -> Ok Public_subkey
    | _ -> Ok Unknown_packet

  let name packet =
    match packet with
    | Session_key -> "Session key packet"
    | Signature -> "Signature packet"
    | Secret_key -> "Secret Key packet"
    | Public_key -> "Public key packet"
    | Secret_subkey -> "Secret subkey packet"
    | Id -> "Identity packet"
    | Public_subkey -> "Public subkey packet"
    | Unknown_packet -> "Unknown packet"

  module Header = struct
    type t =
      { packet_type : packet_type
      ; packet_length : int64
      ; is_new : bool }
    [@@deriving ord, eq, show]

    let is_new_type header_code =
      if header_code >= 192 then
        true
      else
        false

    let get_tag header_code =
      if is_new_type header_code then
        header_code - 192
      else
        (header_code - 128) / 4

    let get_old_length_size length_tag =
      match length_tag with
      | 0 -> Ok 2
      | 1 -> Ok 3
      | 2 -> Ok 5
      | 3 -> Error "Length size not implemented"
      | _ -> Error "Bad length size"

    let get_old_length cs header_code =
      get_old_length_size (header_code mod 4) >>= fun n ->
      match n with
      | 2 -> Ok (n, Int64.of_int (Cstruct.get_uint8 cs 1))
      | 3 -> Ok (n, Int64.of_int (Cstruct.BE.get_uint16 cs 1))
      | 5 -> Ok (n, Int64.of_int32 (Cstruct.BE.get_uint32 cs 1))
      | _ -> Error "Bad length size"

    let get_new_length cs =
      let first_octet = Cstruct.get_uint8 cs 1 in
      if first_octet < 192 then
        Ok (2, Int64.of_int first_octet)
      else if first_octet < 224 then
        let second_octet = Cstruct.get_uint8 cs 2 in
        let length = 192 + second_octet + (256 * (first_octet - 192)) in
        Ok (3, Int64.of_int length)
      else if first_octet < 255 then
        Error "Partial body lengths are not treated"
      else
        let length = Cstruct.BE.get_uint32 cs 2 in
        Ok (6, Int64.of_int32 length)

    let decode cs =
      let header_code = Cstruct.get_uint8 cs 0 in
      let tag = get_tag header_code in
      let length_infos =
        if is_new_type header_code then
          get_new_length cs
        else
          get_old_length cs header_code
      in
      match length_infos with
      | Error _ -> Error Fatal
      | Ok (header_length, packet_length) -> (
        match detag tag with
        | Ok packet_type ->
          Ok
            ( header_length
            , {packet_type; packet_length; is_new = is_new_type header_code} )
        | Error _ -> Error (Header (header_length, packet_length)))

    let print_infos header =
      print_string
        (match header.is_new with
        | true -> "New type of "
        | false -> "Old type of ");
      print_string (name header.packet_type ^ " of length ");
      print_string (Int64.to_string header.packet_length)
  end

  module Id = struct
    type t =
      { name : string
      ; email : string }
    [@@deriving ord, eq, show]

    let print_infos id =
      print_endline ("  name : " ^ id.name);
      print_endline ("  email : " ^ id.email)

    let decode cs =
      let id = Cstruct.to_string cs in
      let sep_id = String.split_on_char '<' id in
      let name = String.concat "<" (List.rev (List.tl (List.rev sep_id))) in
      let email = List.nth sep_id (List.length sep_id - 1) in
      {name; email = String.sub email 0 (String.length email - 1)}
  end

  (*module Signature = struct
    module Subpacket = struct
      type subpacket =
        | Creation_time
        | Expiration_time
        | Export_certification
        | Trust_sig
        | Regular_expression
        | Revocable
        | Key_expiration_time
        | Preferred_sym_algo
        | Revocation_key
        | Issuer
        | Notation_data
        | Preferred_hash_algo
        | Preferred_comp_algo
        | Keyserver_pref
        | Preferred_keyserver
        | Prim_user_id
        | Policy_url
        | Key_flags
        | Signer_user_id
        | Reason_revocation
        | Feature
        | Sig_target
        | Embedded_sig
        | Issuer_fingerprint
        | Preferred_aeded_algo
        | Unknown_subpacket

      type t =
        | Sub_creation_time of int64
        | Sub_expiration_time of int64
        | Sub_export_certification of bool
        | Sub_trust_sig of int * int
        | Sub_revocable of bool
        | Sub_key_expiration_time of int64
        | Sub_issuer of int64
        | Sub_prim_user_id of bool
        | Sub_signer_user_id of string
        | Sub_embedded_sig (* This type has to be moved so this can be defined. *)
        | Sub_issuer_fingerprint of int * string
      [@@deriving ord, eq, show]

      type subpacket_data =
        | Useful of t
        | Useless

      let detag tag =
        match tag with
        | 2 -> Creation_time
        | 3 -> Expiration_time
        | 4 -> Export_certification
        | 5 -> Trust_sig
        | 6 -> Regular_expression
        | 7 -> Revocable
        | 9 -> Key_expiration_time
        | 11 -> Preferred_sym_algo
        | 12 -> Revocation_key
        | 16 -> Issuer
        | 20 -> Notation_data
        | 21 -> Preferred_hash_algo
        | 22 -> Preferred_comp_algo
        | 23 -> Keyserver_pref
        | 24 -> Preferred_keyserver
        | 25 -> Prim_user_id
        | 26 -> Policy_url
        | 27 -> Key_flags
        | 28 -> Signer_user_id
        | 29 -> Reason_revocation
        | 30 -> Feature
        | 31 -> Sig_target
        | 32 -> Embedded_sig
        | 33 -> Issuer_fingerprint
        | 34 -> Preferred_aeded_algo
        | _ -> Unknown_subpacket

      let print_infos subpacket =
        match subpacket with
        | Sub_creation_time creation_time ->
          print_endline ("   Creation time : " ^ Int64.to_string creation_time)
        | Sub_expiration_time expiration_time ->
          print_endline
            ("   Expiration time : " ^ Int64.to_string expiration_time)
        | Sub_export_certification flag -> (
          match flag with
          | true -> print_endline "   This signature is exportable."
          | false -> print_endline "   This signature is not exportable.")
        | Sub_trust_sig (depth, amount) ->
          print_endline
            ("   This signature has a trust depth of "
            ^ Int.to_string depth
            ^ " and amount of "
            ^ Int.to_string amount
            ^ ".")
        | Sub_revocable flag -> (
          match flag with
          | true -> print_endline "   This signature is revocable."
          | false -> print_endline "   This signature is not revocable.")
        | Sub_key_expiration_time expiration_time ->
          print_endline
            ("   Expiration time of the subkey : "
            ^ Int64.to_string expiration_time)
        | Sub_issuer key_id ->
          let id = Printf.sprintf "%Lx" key_id in
          print_endline ("   The key id is " ^ id)
        | Sub_prim_user_id flag -> (
          match flag with
          | true -> print_endline "   This user is the main user of this key."
          | false ->
            print_endline "   This user is not the main user of this key.")
        | Sub_signer_user_id id -> print_endline ("   The signer's ID is " ^ id)
        | Sub_embedded_sig -> ()
        | Sub_issuer_fingerprint (_, fingerprint) ->
          print_string "   The Issuer's fingerprint is : ";
          let fingerprint_seq = String.to_seq fingerprint in
          Seq.iter
            (fun c -> print_string (Printf.sprintf "%02X " (Char.code c)))
            fingerprint_seq

      let header_length cs =
        let first_octet = Cstruct.get_uint8 cs 0 in
        if first_octet < 192 then
          (1, Int64.of_int first_octet)
        else if first_octet < 224 then
          let second_octet = Cstruct.get_uint8 cs 1 in
          let length = 192 + second_octet + (256 * (first_octet - 192)) in
          (2, Int64.of_int length)
        else if first_octet < 255 then
          raise (Subpacket "Partial body length are not treated.")
        else
          let length = Cstruct.BE.get_uint32 cs 1 in
          (5, Int64.of_int32 length)

      let decode cs =
        let tag = Cstruct.get_uint8 cs 0 in
        let subpacket_sigtype = detag tag in
        match subpacket_sigtype with
        | Creation_time ->
          let creation_time = Cstruct.BE.get_uint32 cs 1 in
          Useful (Sub_creation_time (Int64.of_int32 creation_time))
        | Expiration_time ->
          let expiration_time = Cstruct.BE.get_uint32 cs 1 in
          Useful (Sub_expiration_time (Int64.of_int32 expiration_time))
        | Export_certification -> (
          match Cstruct.get_uint8 cs 1 with
          | 0 -> Useful (Sub_export_certification false)
          | 1 -> Useful (Sub_export_certification true)
          | _ -> raise (Subpacket "Exportable flag should be 0 or 1"))
        | Revocable -> (
          match Cstruct.get_uint8 cs 1 with
          | 0 -> Useful (Sub_revocable false)
          | 1 -> Useful (Sub_revocable true)
          | _ -> raise (Subpacket "Revocable flag should be 0 or 1"))
        | Trust_sig ->
          let depth = Cstruct.get_uint8 cs 1 in
          let amount = Cstruct.get_uint8 cs 2 in
          Useful (Sub_trust_sig (depth, amount))
        | Key_expiration_time ->
          let expiration_time = Cstruct.BE.get_uint32 cs 1 in
          Useful (Sub_expiration_time (Int64.of_int32 expiration_time))
        | Issuer ->
          let issuer_keyid = Cstruct.BE.get_uint64 cs 1 in
          Useful (Sub_issuer issuer_keyid)
        | Prim_user_id -> (
          match Cstruct.get_uint8 cs 1 with
          | 0 -> Useful (Sub_prim_user_id false)
          | 1 -> Useful (Sub_prim_user_id true)
          | _ -> raise (Subpacket "Primary User ID flag should be 0 or 1"))
        | Signer_user_id ->
          let str = Cstruct.to_string (Cstruct.shift cs 1) in
          Useful (Sub_signer_user_id str)
        | Issuer_fingerprint ->
          let version = Cstruct.get_uint8 cs 1 in
          let _fingerprint = Cstruct.sub cs 2 20 in
          let fingerprint = Cstruct.to_string _fingerprint in
          Useful (Sub_issuer_fingerprint (version, fingerprint))
        | Preferred_aeded_algo
        | Regular_expression
        | Preferred_keyserver
        | Keyserver_pref
        | Notation_data
        | Preferred_sym_algo
        | Preferred_comp_algo
        | Preferred_hash_algo
        | Feature
        | Policy_url
        | Key_flags
        | Reason_revocation
        | Sig_target
        | Revocation_key
        | Embedded_sig
        | Unknown_subpacket ->
          Useless
    end

    type signature_type =
      | Binary_doc_sig
      | Textdoc_sig
      | Standalone_sig
      | Generic_certif
      | Persona_certif
      | Casual_certif
      | Positive_certif
      | Subkey_binding
      | Primkey_binding
      | Key_sig
      | Key_revocation
      | Subkey_revocation
      | Certif_revocation
      | Timestamp_sig
      | Thirdparty_confirm
    [@@deriving ord, eq, show]

    let name sigtype =
      match sigtype with
      | Binary_doc_sig -> "Signature of a binary document"
      | Textdoc_sig -> "Signature of a canonical text document"
      | Standalone_sig -> "Standalone signature of its own subpacket"
      | Generic_certif ->
        "Generic certification of a User ID and Public key packet"
      | Persona_certif ->
        "Persona certification of a User ID and Public key packet"
      | Casual_certif ->
        "Casual certification of a User ID and Public key packet"
      | Positive_certif ->
        "Positive certification of a User ID and Public key packet"
      | Subkey_binding -> "Subkey binding signature"
      | Primkey_binding -> "Primary key binding signature"
      | Key_sig -> "Signature directly on a key"
      | Key_revocation -> "Key revocation signature"
      | Subkey_revocation -> "Subkey revocation signature"
      | Certif_revocation -> "Certification revocation signature"
      | Timestamp_sig -> "Timestamp signature"
      | Thirdparty_confirm -> "Third-Party confirmation signature"

    let detag tag =
      match tag with
      | 0 -> Binary_doc_sig
      | 1 -> Textdoc_sig
      | 2 -> Standalone_sig
      | 16 -> Generic_certif
      | 17 -> Persona_certif
      | 18 -> Casual_certif
      | 19 -> Positive_certif
      | 24 -> Subkey_binding
      | 25 -> Primkey_binding
      | 31 -> Key_sig
      | 32 -> Key_revocation
      | 40 -> Subkey_revocation
      | 48 -> Certif_revocation
      | 64 -> Timestamp_sig
      | 80 -> Thirdparty_confirm
      | _ -> raise (Signature "Incorrect tag for signature type.")

    module Value = struct
      type t =
        | Rsa of Rsa.Signature.t
        | Dsa of Dsa.Signature.t
      [@@deriving ord, eq, show]
    end

    type t =
      { version : int
      ; signature_type : signature_type
      ; public_algorithm : Algo.Public.t
      ; hash_algorithm : Algo.Hash.t
      ; signature : Value.t
      ; hash : string
      ; subpacket_data : Subpacket.t list }
    [@@deriving ord, eq, show]

    let print_infos signature =
      print_endline ("  Version " ^ Int.to_string signature.version);
      print_endline ("  Signature type : " ^ name signature.signature_type);
      print_endline
        ("  Public algorithm : " ^ Algo.Public.name signature.public_algorithm);
      print_endline
        ("  Hash algorithm : " ^ Algo.Hash.name signature.hash_algorithm);
      List.iter Subpacket.print_infos signature.subpacket_data;
      print_newline ()

    let decode_algo (algo : Algo.Public.t) cs =
      match algo with
      | Rsa_enc_sign
      | Rsa_sign_only ->
        let (_, s) = decode_mpi cs 2 in
        Value.Rsa s
      | Dsa ->
        let (r_length, r) = decode_mpi cs 2 in
        let (_, s) = decode_mpi cs (4 + r_length) in
        Dsa Dsa.Signature.{r; s}
      | Rsa_enc_only ->
        raise (Signature "Decoding signatures of this algorithm is impossible.")
      | Elgamal_sign_only
      | Ec
      | Ecdsa
      | Unknown ->
        raise
          (Signature "Decoding signatures of this algorithm is not implemented.")

    let rec signature_data cs data length =
      match length with
      | 0 -> data
      | _ -> (
        let (header_length, subpacket_length) = Subpacket.header_length cs in
        let subcs = Cstruct.shift cs header_length in
        let subpacket_data = Subpacket.decode subcs in
        let cs_rec = Cstruct.shift subcs (Int64.to_int subpacket_length) in
        match subpacket_data with
        | Useful sub_data ->
          signature_data cs_rec (sub_data :: data)
            (length - header_length - Int64.to_int subpacket_length)
        | Useless ->
          signature_data cs_rec data
            (length - header_length - Int64.to_int subpacket_length))

    let decode_recent packet version =
      let sigtype_tag = Cstruct.get_uint8 packet 1 in
      let sigtype = detag sigtype_tag in
      let pub_algo_tag = Cstruct.get_uint8 packet 2 in
      let pub_algo = Algo.Public.detag pub_algo_tag in
      let hash_algo_tag = Cstruct.get_uint8 packet 3 in
      let hash_algo = Algo.Hash.detag hash_algo_tag in
      let hashed_subdata_length = Cstruct.BE.get_uint16 packet 4 in
      let skipped_hashed_data =
        Cstruct.shift packet (6 + hashed_subdata_length)
      in
      (* We just read 3 int8 and one int16 coming from an offset of 1*)
      let unhashed_data_length = Cstruct.BE.get_uint16 skipped_hashed_data 0 in
      let hashed_cs = Cstruct.sub packet 6 hashed_subdata_length in
      let unhashed_cs =
        Cstruct.sub skipped_hashed_data 2 unhashed_data_length
      in
      let subpacket_cs = Cstruct.concat [hashed_cs; unhashed_cs] in
      let subpacket_length = Cstruct.length subpacket_cs in
      let subpacket_data = signature_data subpacket_cs [] subpacket_length in
      let skipped_subpacket_data =
        Cstruct.shift skipped_hashed_data (2 + unhashed_data_length)
      in
      let hash_int = Cstruct.get_uint8 skipped_subpacket_data 0 in
      let hash = Printf.sprintf "%04x" hash_int in
      let signature = decode_algo pub_algo skipped_subpacket_data in
      { version
      ; signature_type = sigtype
      ; public_algorithm = pub_algo
      ; hash_algorithm = hash_algo
      ; signature
      ; hash
      ; subpacket_data }

    let decode packet =
      let version = Cstruct.get_uint8 packet 0 in
      match version with
      | 3 -> raise (Signature "Version 3 signatures not supported.")
      | 4
      | 5 ->
        decode_recent packet version
      | _ -> raise (Signature "Incorrect signature version number.")
    end*)

  module Public_key = struct
    module Public_key_value = struct
      type t =
        | Rsa of Rsa.Public.t
        | Dsa of Dsa.Public.t
        | Elgamal of Elgamal.Public.t
      [@@deriving ord, eq, show]
    end

    type t =
      { version : int
      ; creation_time : int32
      ; validity_period : int option
      ; algo : Algo.Public.t
      ; public_key : Public_key_value.t }
    [@@deriving ord, eq, show]

    let print_infos public_key =
      print_endline ("  Version " ^ Int.to_string public_key.version);
      print_endline
        ("  Creation time : " ^ Int32.to_string public_key.creation_time);
      print_endline ("  Algorithm: " ^ Algo.Public.name public_key.algo)

    let decode_public_key (algo : Algo.Public.t) packet version =
      let offset =
        (*A public key packet has another header*)
        match version with
        | 3 ->
          Ok 8
          (*and a version 3 public key packet also contains a validity period*)
        | 4 -> Ok 6
        | _ -> Error "Public key packet has a bad version"
      in
      offset >>= fun offset ->
      match algo with
      | Rsa_enc_sign
      | Rsa_enc_only
      | Rsa_sign_only ->
        let (cs, key) = Rsa.Public.decode packet offset in
        Ok (cs, Public_key_value.Rsa key)
      | Dsa ->
        let (cs, key) = Dsa.Public.decode packet offset in
        Ok (cs, Dsa key)
      | Elgamal_sign_only ->
        let (cs, key) = Elgamal.Public.decode packet offset in
        Ok (cs, Elgamal key)
      | Ec
      | Ecdsa
      | Unknown ->
        Error ("Unsupported algorithm: " ^ Algo.Public.name algo)

    let decode packet =
      let version = Cstruct.get_uint8 packet 0 in
      let creation_time = Cstruct.BE.get_uint32 packet 1 in
      let packet_infos =
        match version with
        | 4 -> Ok (packet, None)
        | 2
        | 3 ->
          let time = Cstruct.BE.get_uint16 packet 5 in
          let cs = Cstruct.shift packet 2 in
          Ok (cs, Some time)
        | _ -> Error "Bad version of public key packet."
      in
      let algo = Algo.Public.detag (Cstruct.get_uint8 packet 5) in
      match packet_infos with
      | Ok (public_packet, validity_period) ->
        decode_public_key algo public_packet version >|= fun (cs, key) ->
        (cs, {version; creation_time; validity_period; algo; public_key = key})
      | Error _ -> Error "error"
  end

  module Private_key_value = struct
    type t =
      | Rsa of Rsa.Private.t
      | Dsa of Dsa.Private.t
      | Elgamal of Elgamal.Private.t
    [@@deriving ord, eq, show]
  end

  module Secret_key = struct
    module S2k = struct
      type s2k_type =
        | Simple
        | Salted
        | Iterated_salted
        | Unknown

      let detag tag =
        match tag with
        | 0 -> Simple
        | 1 -> Salted
        | 3 -> Iterated_salted
        | _ -> Unknown

      let name specifier =
        match specifier with
        | Simple -> "Simple String2Key"
        | Salted -> "Salted String2Key"
        | Iterated_salted -> "Iterated&Salted String2Key"
        | Unknown -> "Unknown String2Key"

      type t =
        | Simple of Algo.Hash.t
        | Salted of Algo.Hash.t * int64
        | Iterated_salted of Algo.Hash.t * int64 * int
      [@@deriving ord, eq, show]

      let print_infos s2k =
        match s2k with
        | Simple algo ->
          print_endline
            ("   Simple S2k using " ^ Algo.Hash.name algo ^ " algorithm")
        | Salted (algo, _) ->
          print_endline
            ("   Salted S2k using " ^ Algo.Hash.name algo ^ " algorithm")
        | Iterated_salted (algo, _, _) ->
          print_endline
            ("   Iterated & Salted S2k using "
            ^ Algo.Hash.name algo
            ^ " algorithm")
    end

    type t =
      { public_key : Public_key.t
      ; s2k : S2k.t option
      ; initial_vector : string option
      ; private_key : Private_key_value.t option
      ; checksum : string option
      ; hash : string option }
    [@@deriving ord, eq, show]

    let decode_s2k packet s2k_specifier =
      let hash_tag = Cstruct.get_uint8 packet 3 in
      let hash_algo = Algo.Hash.detag hash_tag in
      match s2k_specifier with
      | S2k.Unknown -> Error "Unknown String2key"
      | Simple -> Ok (S2k.Simple hash_algo, 4)
      | Salted ->
        let salt_value = Cstruct.BE.get_uint64 packet 4 in
        Ok (S2k.Salted (hash_algo, salt_value), 12)
      | Iterated_salted ->
        let salt_value = Cstruct.BE.get_uint64 packet 4 in
        let count = Cstruct.get_uint8 packet 12 in
        Ok (S2k.Iterated_salted (hash_algo, salt_value, count), 13)

    let decode_private_key packet (algo : Algo.Public.t) =
      match algo with
      | Rsa_enc_sign
      | Rsa_enc_only
      | Rsa_sign_only ->
        let (cs, key) = Rsa.Private.decode packet 0 in
        Ok (cs, Private_key_value.Rsa key)
      | Dsa ->
        let (cs, key) = Dsa.Private.decode packet 0 in
        Ok (cs, Dsa key)
      | Elgamal_sign_only ->
        let (cs, key) = Elgamal.Private.decode packet 0 in
        Ok (cs, Elgamal key)
      | Ec
      | Ecdsa
      | Unknown ->
        Error ("Not implemented for algorithm:" ^ Algo.Public.name algo)

    let decode_convention (public_key : Public_key.t) packet convention =
      match convention with
      | 0 ->
        let secret_packet = Cstruct.shift packet 1 in
        decode_private_key secret_packet public_key.algo
        >|= fun (cs, private_key) ->
        let checksum_int = Cstruct.BE.get_uint16 cs 0 in
        let checksum = Z.format "0x0100" (Z.of_int checksum_int) in
        { public_key
        ; s2k = None
        ; initial_vector = None
        ; private_key = Some private_key
        ; checksum = Some checksum
        ; hash = None }
      | 254 ->
        let sym_tag = Cstruct.get_uint8 packet 1 in
        let sym_algo = Algo.Symmetric.detag sym_tag in
        let s2k_tag = Cstruct.get_uint8 packet 2 in
        let s2k_specifier = S2k.detag s2k_tag in
        decode_s2k packet s2k_specifier >|= fun (s2k, off) ->
        let cs_shifted = Cstruct.shift packet off in
        let cipher_block = Algo.Symmetric.size sym_algo in
        let initial_vector_z = get_z_be cs_shifted 0 cipher_block in
        let initial_vector = Z.format "0x100" initial_vector_z in
        { s2k = Some s2k
        ; public_key
        ; initial_vector = Some initial_vector
        ; private_key = None
        ; hash = None
        ; checksum = None }
      | _ -> Error "Private key type not treated."

    let decode packet =
      Public_key.decode packet >>= fun (cs, public_key) ->
      let offset =
        match public_key.version with
        | 3 -> Ok 8
        | 4 -> Ok 6
        | _ -> Error "Bad version of Public key packet"
      in
      offset >>= fun offset ->
      let secret_packet = Cstruct.shift cs offset in
      let convention = Cstruct.get_uint8 secret_packet 0 in
      decode_convention public_key secret_packet convention

    let print_infos private_key =
      print_endline "  Informations on the public key :";
      Public_key.print_infos private_key.public_key;
      print_endline "  Informations on the private key :";
      match private_key.s2k with
      | None -> print_endline "   Private key is not encrypted."
      | Some s2k -> (
        print_endline "   Private key is encrypted using a String2Key :";
        S2k.print_infos s2k;
        match private_key.initial_vector with
        | Some initial_vector ->
          print_endline ("   Initialisation vector is :" ^ initial_vector)
        | None -> ())
  end
  [@@deriving ord, eq, show]

  module Body = struct
    type t =
      | Id of Id.t
      | Secret_key of Secret_key.t
      | Public_key of Public_key.t
      | Signature (*of Signature.t*)
      | Secret_subkey of Secret_key.t
      | Public_subkey of Public_key.t
      | Unknown
    [@@deriving ord, eq, show]

    let decode packet_type packet =
      match (packet_type : packet_type) with
      | Id -> Ok (Id (Id.decode packet))
      | Secret_key -> Secret_key.decode packet >|= fun key -> Secret_key key
      | Public_key ->
        Public_key.decode packet >|= fun (_, key) -> Public_key key
      | Signature -> Ok Unknown (*Signature (Signature.decode packet)*)
      | Secret_subkey ->
        Secret_key.decode packet >|= fun key -> Secret_subkey key
      | Public_subkey ->
        Public_key.decode packet >|= fun (_, key) -> Public_subkey key
      | Session_key
      | Unknown_packet ->
        Ok Unknown
  end

  type t =
    { header : Header.t
    ; packet : Body.t }
  [@@deriving ord, eq, show]

  let decode cs =
    match Header.decode cs with
    | Ok (header_length, header) -> (
      let packet_cs =
        Cstruct.sub cs header_length (Int64.to_int header.packet_length)
      in
      let res = Body.decode header.packet_type packet_cs in
      match res with
      | Error _ ->
        let next_cs =
          Cstruct.shift cs (header_length + Int64.to_int header.packet_length)
        in
        Error next_cs
      (*When a packet can't be parsed, but the header is correct*)
      | Ok packet ->
        let next_cs =
          Cstruct.shift cs (header_length + Int64.to_int header.packet_length)
        in
        Ok (next_cs, {header; packet}))
    | Error Fatal -> Error Cstruct.empty
    (* When the length of the header can't be parsed *)
    | Error (Header (header_length, packet_length)) ->
      (*When the length of the header can be parsed*)
      let next_cs =
        Cstruct.shift cs (header_length + Int64.to_int packet_length)
      in
      Error next_cs

  let print_infos packet =
    Header.print_infos packet.header;
    (match packet.packet with
    | Id id_packet -> Id.print_infos id_packet
    | Secret_key secret_key_packet -> Secret_key.print_infos secret_key_packet
    | Public_key public_key_packet -> Public_key.print_infos public_key_packet
    | Signature -> print_newline () (*Signature.print_infos signature_packet*)
    | Secret_subkey secretsubkey_packet ->
      Secret_key.print_infos secretsubkey_packet
    | Public_subkey public_subkey -> Public_key.print_infos public_subkey
    | Unknown -> print_newline ());
    print_newline ()
end

let rec decode cs packet_list =
  if Cstruct.length cs != 0 then
    match Packet.decode cs with
    | Ok (next_cs, packet) -> decode next_cs (packet :: packet_list)
    | Error next_cs -> decode next_cs packet_list
  else
    List.rev packet_list
