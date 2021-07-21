exception LengthBlock of string

exception PacketTag of string

exception Algo of string

exception Packet of string

exception Subpacket of string

exception Signature of string

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
      | i -> raise (Algo ("Algorithm not found : tag " ^ Int.to_string i))

    let name algo =
      match algo with
      | Rsa_enc_sign -> "RSA Encryption & Signature"
      | Rsa_enc_only -> "RSA Encryption only"
      | Rsa_sign_only -> "RSA Signature only"
      | Elgamal_sign_only -> "Elgamal Signature only"
      | Dsa -> "DSA"
      | Ec -> "EC"
      | Ecdsa -> "ECDSA"
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
    [@@deriving ord, eq, show]

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
      | _ -> raise (Algo "Hash algorithm not found.")
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
      ; e : Derivable.Z.t
      ; length : int }
    [@@deriving ord, eq, show]

    let decode packet off =
      let (n_length, n) = decode_mpi packet off in
      let (e_length, e) = decode_mpi packet (n_length + off + 2) in
      let length = n_length + e_length + 4 in
      let public_key = {n; e; length} in
      `Rsa public_key
  end

  module Private = struct
    type t =
      { d : Derivable.Z.t
      ; p : Derivable.Z.t
      ; q : Derivable.Z.t
      ; u : Derivable.Z.t
      ; length : int }
    [@@deriving ord, eq, show]

    let decode packet off =
      let (d_length, d) = decode_mpi packet off in
      let (p_length, p) = decode_mpi packet (d_length + off + 2) in
      let (q_length, q) = decode_mpi packet (d_length + p_length + off + 4) in
      let (u_length, u) =
        decode_mpi packet (d_length + p_length + q_length + off + 6)
      in
      print_newline ();
      let length = d_length + p_length + q_length + off + u_length + 8 in
      `Rsa {d; p; q; u; length}
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
      ; y : Derivable.Z.t
      ; length : int }
    [@@deriving ord, eq, show]

    let decode packet off =
      let (p_length, p) = decode_mpi packet off in
      let (q_length, q) = decode_mpi packet (p_length + off + 2) in
      let (g_length, g) = decode_mpi packet (p_length + q_length + off + 4) in
      let (y_length, y) =
        decode_mpi packet (p_length + q_length + g_length + off + 6)
      in
      let length = p_length + q_length + g_length + y_length + 8 in
      `Dsa {p; q; g; y; length}
  end

  module Private = struct
    type t =
      { x : Derivable.Z.t
      ; length : int }
    [@@deriving ord, eq, show]

    let decode packet off =
      let (length, x) = decode_mpi packet off in
      `Dsa {x; length = length + 2}
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
      ; y : Derivable.Z.t
      ; length : int }
    [@@deriving ord, eq, show]

    let decode packet off =
      let (p_length, p) = decode_mpi packet off in
      let (g_length, g) = decode_mpi packet (p_length + off + 2) in
      let (y_length, y) = decode_mpi packet (p_length + g_length + off + 4) in
      let length = p_length + g_length + y_length + off + 6 in
      let public_key = {p; g; y; length} in
      `Elgamal public_key
  end
  [@@deriving ord, eq, show]

  module Private = struct
    type t =
      { x : Derivable.Z.t
      ; length : int }
    [@@deriving ord, eq, show]

    let decode packet off =
      let (length, x) = decode_mpi packet off in
      `Elgamal {x; length = length + 2}
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
    | 0 -> raise (PacketTag "A packet can't have tag 0.")
    | 1 -> Session_key
    | 2 -> Unknown_packet (*Signature*)
    | 5 -> Secret_key
    | 6 -> Public_key
    | 7 -> Secret_subkey
    | 13 -> Id
    | 14 -> Public_subkey
    | _ -> Unknown_packet

  let name packet =
    match packet with
    | Session_key -> "Session key packet"
    | Signature -> "Signature packet"
    | Secret_key -> "Secret Key packet"
    | Public_key -> "Public key packet"
    | Secret_subkey -> "Secret subkey packet"
    | Id -> "Identity packet"
    | Public_subkey -> "Public subkey packet"
    | _ -> "Unknown packet"

  module Header = struct
    type t =
      { packet_type : packet_type
      ; length_size : int
      ; length : int64
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
      | 0 -> 1
      | 1 -> 2
      | 2 -> 4
      | 3 -> raise (LengthBlock "Not implemented.")
      | _ -> raise (LengthBlock "Length block doesn't have a correct value.")

    let get_old_length cs header_code =
      let length_size = get_old_length_size (header_code mod 4) in
      let length =
        match length_size with
        | 1 -> Int64.of_int (Cstruct.get_uint8 cs 1)
        | 2 -> Int64.of_int (Cstruct.BE.get_uint16 cs 1)
        | 4 -> Int64.of_int32 (Cstruct.BE.get_uint32 cs 1)
        | _ -> raise (LengthBlock "Length block doesn't have a correct value.")
      in
      (length_size, length)

    let get_new_length cs =
      let first_octet = Cstruct.get_uint8 cs 1 in
      if first_octet < 192 then
        (1, Int64.of_int first_octet)
      else if first_octet < 224 then
        let second_octet = Cstruct.get_uint8 cs 2 in
        let length = 192 + second_octet + (256 * (first_octet - 192)) in
        (2, Int64.of_int length)
      else if first_octet < 255 then
        raise (LengthBlock "Partial body length are not treated.")
      else
        let length = Cstruct.BE.get_uint32 cs 2 in
        (5, Int64.of_int32 length)

    let decode cs =
      let header_code = Cstruct.get_uint8 cs 0 in
      let tag = get_tag header_code in
      let (length_size, length) =
        if is_new_type header_code then
          get_new_length cs
        else
          get_old_length cs header_code
      in

      { packet_type = detag tag
      ; length_size
      ; length
      ; is_new = is_new_type header_code }
      [@@deriving ord, eq, show]

    let print_infos header =
      print_string
        (match header.is_new with
        | true -> "New type of "
        | false -> "Old type of ");
      print_string (name header.packet_type ^ " of length ");
      print_string (Int64.to_string header.length);
      print_string " (+";
      print_int header.length_size;
      print_string " octets for the size of the header).\n"
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

  module Signature = struct
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
          raise (LengthBlock "Partial body length are not treated.")
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
        [ `Rsa of Rsa.Signature.t
        | `Dsa of Dsa.Signature.t ]
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
        `Rsa s
      | Dsa ->
        let (r_length, r) = decode_mpi cs 2 in
        let (_, s) = decode_mpi cs (4 + r_length) in
        `Dsa Dsa.Signature.{r; s}
      | _ ->
        raise (Algo "Decoding signatures of this algorithm is not implemented.")

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
  end
  [@@deriving ord, eq, show]

  module Public_key = struct
    module Public_key_value = struct
      type t =
        [ `Rsa of Rsa.Public.t
        | `Dsa of Dsa.Public.t
        | `Elgamal of Elgamal.Public.t ]
      [@@deriving ord, eq, show]
    end

    type t =
      { version : int
      ; creation_time : int
      ; validity_period : int option
      ; algo : Algo.Public.t
      ; public_key : Public_key_value.t }
    [@@deriving ord, eq, show]

    let print_infos public_key =
      print_endline ("  Version " ^ Int.to_string public_key.version);
      print_endline
        ("  Creation time : " ^ Int.to_string public_key.creation_time);
      print_endline ("  Algorithm : " ^ Algo.Public.name public_key.algo)

    let get_length (public_key : Public_key_value.t) =
      match public_key with
      | `Rsa key -> key.length
      | `Dsa key -> key.length
      | `Elgamal key -> key.length

    let decode_public_key (algo : Algo.Public.t) packet =
      match algo with
      | Rsa_enc_sign
      | Rsa_enc_only
      | Rsa_sign_only ->
        Rsa.Public.decode packet 6
      | Dsa -> Dsa.Public.decode packet 6
      | Elgamal_sign_only -> Elgamal.Public.decode packet 6
      | _ -> raise (Algo "Not implemented.")

    let decode packet =
      let version = Cstruct.get_uint8 packet 0 in
      let creation_time = Cstruct.BE.get_uint32 packet 1 in
      let (public_packet, validity_period) =
        match version with
        | 4 -> (packet, None)
        | 2
        | 3 ->
          let time = Cstruct.BE.get_uint16 packet 5 in
          let cs = Cstruct.shift packet 2 in
          (cs, Some time)
        | _ -> raise (Packet "Bad version of public key packet.")
      in
      let algo = Algo.Public.detag (Cstruct.get_uint8 packet 5) in
      let key = decode_public_key algo public_packet in
      { version
      ; creation_time = Int32.to_int creation_time
      ; validity_period
      ; algo
      ; public_key = key }
  end
  [@@deriving ord, eq, show]

  module Private_key_value = struct
    type t =
      [ `Rsa of Rsa.Private.t
      | `Dsa of Dsa.Private.t
      | `Elgamal of Elgamal.Private.t ]
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

    let get_length (private_key : Private_key_value.t) =
      match private_key with
      | `Rsa key -> key.length
      | `Dsa key -> key.length
      | `Elgamal key -> key.length

    let decode_s2k packet s2k_specifier =
      let hash_tag = Cstruct.get_uint8 packet 3 in
      let hash_algo = Algo.Hash.detag hash_tag in
      match s2k_specifier with
      | S2k.Unknown -> raise (Packet "Unknown S2K")
      | Simple -> (S2k.Simple hash_algo, 4)
      | Salted ->
        let salt_value = Cstruct.BE.get_uint64 packet 4 in
        (S2k.Salted (hash_algo, salt_value), 12)
      | Iterated_salted ->
        let salt_value = Cstruct.BE.get_uint64 packet 4 in
        let count = Cstruct.get_uint8 packet 12 in
        (S2k.Iterated_salted (hash_algo, salt_value, count), 13)

    let decode_private_key packet (algo : Algo.Public.t) =
      match algo with
      | Rsa_enc_sign
      | Rsa_enc_only
      | Rsa_sign_only ->
        Rsa.Private.decode packet 0
      | Dsa -> Dsa.Private.decode packet 0
      | Elgamal_sign_only -> Elgamal.Private.decode packet 0
      | _ -> raise (Algo "Not implemented.")

    let decode_convention (public_key : Public_key.t) packet convention =
      match convention with
      | 0 ->
        let secret_packet = Cstruct.shift packet 1 in
        let private_key = decode_private_key secret_packet public_key.algo in
        let off = get_length private_key in
        let checksum_int = Cstruct.BE.get_uint16 secret_packet off in
        let checksum = Z.format "0x0100" (Z.of_int checksum_int) in
        { public_key
        ; s2k = None
        ; initial_vector = None
        ; private_key = Some private_key
        ; checksum = Some checksum
        ; hash = None }
      | 254
      | 255 ->
        raise (Packet "Private key type not treated.")
      (*let sym_tag = Cstruct.get_uint8 packet 1 in
        let sym_algo = Algo.Symmetric.detag sym_tag in
        let s2k_tag = Cstruct.get_uint8 packet 2 in
        let s2k_specifier = S2k.detag s2k_tag in
        let (s2k, off) = decode_s2k packet s2k_specifier in
        let cipher_block = Algo.Symmetric.size sym_algo in
        let initial_vector = Cstruct.sub packet off cipher_block in
        { s2k = Some s2k
        ; public_key
        ; initial_vector = Some initial_vector
        ; private_key = None
        ; hash = None
            ; checksum = None }*)
      | _ -> raise (Packet "Private key type not treated.")
    (*let sym_algo = Algo.Symmetric.detag id in
      let s2k = S2k.Simple Algo.Hash.MD5 in
      let cipher_block = Algo.Symmetric.size sym_algo in
      let initial_vector = Cstruct.sub packet 1 cipher_block in
      { s2k = Some s2k
      ; public_key
      ; initial_vector = Some initial_vector
      ; private_key = None
      ; hash = None
        ; checksum = None }*)

    let decode packet =
      let public_key = Public_key.decode packet in
      let off = 6 + Public_key.get_length public_key.public_key in
      let secret_packet = Cstruct.shift packet off in
      let convention = Cstruct.get_uint8 secret_packet 0 in
      decode_convention public_key secret_packet convention

    let print_infos private_key =
      print_endline "  Informations on the public key :";
      Public_key.print_infos private_key.public_key;
      print_endline "  Informations on the private key :";
      match private_key.s2k with
      | None -> print_endline "   Private key is not encrypted."
      | Some s2k ->
        print_endline "   Private key is encrypted using a String2Key :";
        S2k.print_infos s2k
  end
  [@@deriving ord, eq, show]

  module Body = struct
    type t =
      [ `Id of Id.t
      | `Secret_key of Secret_key.t
      | `Public_key of Public_key.t
      | `Signature of Signature.t
      | `Secret_subkey of Secret_key.t
      | `Public_subkey of Public_key.t
      | `Unknown ]
    [@@deriving ord, eq, show]
  end

  type t =
    { header : Header.t
    ; packet : Body.t }
  [@@deriving ord, eq, show]

  let decode cs =
    let header = Header.decode cs in
    let packet_cs =
      Cstruct.sub cs (1 + header.length_size) (Int64.to_int header.length)
    in
    let (packet : Body.t) =
      match header.packet_type with
      | Id -> `Id (Id.decode packet_cs)
      | Secret_key -> `Secret_key (Secret_key.decode packet_cs)
      | Public_key -> `Public_key (Public_key.decode packet_cs)
      | Signature -> `Unknown (*`Signature (Signature.decode packet_cs)*)
      | Secret_subkey -> `Secret_key (Secret_key.decode packet_cs)
      | Public_subkey -> `Public_key (Public_key.decode packet_cs)
      | _ -> `Unknown
    in
    let next_cs =
      Cstruct.shift cs (1 + header.length_size + Int64.to_int header.length)
    in
    (next_cs, {header; packet})

  let print_infos packet =
    Header.print_infos packet.header;
    (match packet.packet with
    | `Id id_packet -> Id.print_infos id_packet
    | `Secret_key secret_key_packet -> Secret_key.print_infos secret_key_packet
    | `Public_key public_key_packet -> Public_key.print_infos public_key_packet
    | `Signature signature_packet -> Signature.print_infos signature_packet
    | `Secret_subkey secretsubkey_packet ->
      Secret_key.print_infos secretsubkey_packet
    | `Public_subkey public_subkey -> Public_key.print_infos public_subkey
    | _ -> ());
    print_newline ()
end
(* moves after the armoring 

let rec check_offset cs i j =
  let first_val = Cstruct.get_uint8 cs i in
  match first_val with
  | 10 when j == 1 -> i + 1
  | 10 -> check_offset cs (i + 1) (j + 1)
  | 58 -> check_offset cs (i + 1) 0
  | _ -> check_offset cs (i + 1) j

 I copied this from pem_utils.ml (host-scanner) v 

let relaxed_base64_rfc2045_of_string x =
  let decoder = Base64_rfc2045.decoder (`String x) in
  let res = Buffer.create 16 in
  let rec go () =
    match Base64_rfc2045.decode decoder with
    | `End -> ()
    | `Wrong_padding -> go ()
    | `Malformed _ -> go ()
    | `Flush x ->
      Buffer.add_string res x;
      go ()
    | `Await -> ()
  in
  Base64_rfc2045.src decoder (Bytes.unsafe_of_string x) 0 (String.length x);
  go ();
  Buffer.contents res



let decode_base64 cs =
  let off = check_offset cs 0 0 in
  let str = Cstruct.to_string ~off cs in
  let decoded_str = relaxed_base64_rfc2045_of_string str in
  let decoded_cs = Cstruct.of_string decoded_str in
  let res = Packet.decode decoded_cs in
  List.iter Packet.print_infos res

let decode_test cs =
  let header = Header.decode cs in
  let packet = decode_packetXF cs header in
  decode_rec cs header [packet]
  end*)

let advance_cs cs (header : Packet.Header.t) =
  let real_size = header.length_size + Int64.to_int header.length in
  Cstruct.shift cs (real_size + 1)

let rec decode cs packet_list =
  if Cstruct.length cs != 0 then
    let (next_cs, packet) = Packet.decode cs in
    match packet.packet with
    | `Unknown -> decode next_cs packet_list
    | _ -> decode next_cs (packet :: packet_list)
  else
    List.rev packet_list
