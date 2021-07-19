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
      | RSAEncSign
      | RSAEncOnly
      | RSASignOnly
      | ElgaSignOnly
      | DSA
      | EC
      | ECDSA

    let detag tag =
      match tag with
      | 1 -> RSAEncSign
      | 2 -> RSAEncOnly
      | 3 -> RSASignOnly
      | 16 -> ElgaSignOnly
      | 17 -> DSA
      | 18 -> EC
      | 19 -> ECDSA
      | i -> raise (Algo ("Algorithm not found : tag " ^ Int.to_string i))

    let name algo =
      match algo with
      | RSAEncSign -> "RSA Encryption & Signature"
      | RSAEncOnly -> "RSA Encryption only"
      | RSASignOnly -> "RSA Signature only"
      | ElgaSignOnly -> "Elgamal Signature only"
      | DSA -> "DSA"
      | EC -> "EC"
      | ECDSA -> "EC DSA"
  end

  module Hash = struct
    type t =
      | MD5
      | SHA1
      | RIPE_MD160
      | SHA2_256
      | SHA2_384
      | SHA2_512
      | SHA2_224
      | SHA3_256
      | SHA3_512

    let name algo =
      match algo with
      | MD5 -> "MD5"
      | SHA1 -> "SHA1"
      | RIPE_MD160 -> "RIPE_MD160"
      | SHA2_256 -> "SHA2 256"
      | SHA2_384 -> "SHA2 384"
      | SHA2_512 -> "SHA2 512"
      | SHA2_224 -> "SHA2 224"
      | SHA3_256 -> "SHA3 256"
      | SHA3_512 -> "SHA3 512"

    let detag tag =
      match tag with
      | 1 -> MD5
      | 2 -> SHA1
      | 3 -> RIPE_MD160
      | 8 -> SHA2_256
      | 9 -> SHA2_384
      | 10 -> SHA2_512
      | 11 -> SHA2_224
      | 12 -> SHA3_256
      | 14 -> SHA3_512
      | _ -> raise (Algo "Hash algorithm not found.")
  end

  module Symmetric = struct
    type t =
      | Plaintext
      | IDEA
      | TripleDES
      | CAST5
      | Blowfish
      | AES128
      | AES192
      | AES256
      | Twofish256
      | Unknown

    let size algo =
      match algo with
      | Plaintext -> 0
      | IDEA -> 8
      | TripleDES -> 8
      | CAST5 -> 16
      | Blowfish -> 8
      | AES128 -> 16
      | AES192 -> 24
      | AES256 -> 32
      | Twofish256 -> 32
      | Unknown -> 0

    let name algo =
      match algo with
      | Plaintext -> "Plain text"
      | IDEA -> "IDEA"
      | TripleDES -> "Triple DES"
      | CAST5 -> "Cast5"
      | Blowfish -> "Blowfish"
      | AES128 -> "AES 128"
      | AES192 -> "AES 192"
      | AES256 -> "AES 256"
      | Twofish256 -> "Twofish 256"
      | Unknown -> "Unknown symmetric-key algorithm"

    let detag tag =
      match tag with
      | 0 -> Plaintext
      | 1 -> IDEA
      | 2 -> TripleDES
      | 3 -> CAST5
      | 4 -> Blowfish
      | 7 -> AES128
      | 8 -> AES192
      | 9 -> AES256
      | 10 -> Twofish256
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
      `RSA public_key
  end

  module Private = struct
    type t =
      { d : Derivable.Z.t
      ; p : Derivable.Z.t
      ; q : Derivable.Z.t
      ; u : Derivable.Z.t
      ; length : int }

    let decode packet off =
      let (d_length, d) = decode_mpi packet off in
      let (p_length, p) = decode_mpi packet (d_length + off + 2) in
      let (q_length, q) = decode_mpi packet (d_length + p_length + off + 4) in
      let (u_length, u) =
        decode_mpi packet (d_length + p_length + q_length + off + 6)
      in
      let length = d_length + p_length + q_length + off + u_length + 8 in
      `RSA {d; p; q; u; length}
  end
  [@@deriving ord, eq, show]

  module Signature = struct
    type t = Derivable.Z.t
  end
  [@@deriving ord, eq, show]
end

module Dsa = struct
  module Public = struct
    type t =
      { p : Derivable.Z.t
      ; q : Derivable.Z.t
      ; g : Derivable.Z.t
      ; y : Derivable.Z.t
      ; length : int }

    let decode packet off =
      let (p_length, p) = decode_mpi packet off in
      let (q_length, q) = decode_mpi packet (p_length + off + 2) in
      let (g_length, g) = decode_mpi packet (p_length + q_length + off + 4) in
      let (y_length, y) =
        decode_mpi packet (p_length + q_length + g_length + off + 6)
      in
      let length = p_length + q_length + g_length + y_length + 8 in
      `DSA {p; q; g; y; length}
  end
  [@@deriving ord, eq, show]

  module Private = struct
    type t =
      { q : Derivable.Z.t
      ; length : int }

    let decode packet off =
      let (length, q) = decode_mpi packet off in
      `DSA {q; length}
  end
  [@@deriving ord, eq, show]

  module Signature = struct
    type t =
      { r : Derivable.Z.t
      ; s : Derivable.Z.t }
  end
  [@@deriving ord, eq, show]
end

module Elgamal = struct
  module Public = struct
    type t =
      { p : Derivable.Z.t
      ; g : Derivable.Z.t
      ; y : Derivable.Z.t
      ; length : int }

    let decode packet off =
      let (p_length, p) = decode_mpi packet off in
      let (g_length, g) = decode_mpi packet (p_length + off + 2) in
      let (y_length, y) = decode_mpi packet (p_length + g_length + off + 4) in
      let length = p_length + g_length + y_length + off in
      let public_key = {p; g; y; length} in
      `Elgamal public_key
  end
  [@@deriving ord, eq, show]

  module Private = struct
    type t =
      { x : Derivable.Z.t
      ; length : int }

    let decode packet off =
      let (length, x) = decode_mpi packet off in
      `Elgamal {x; length}
  end
  [@@deriving ord, eq, show]
end

module Packet = struct
  type packet_type =
    | SessionKey
    | Signature
    | SecretKey
    | PublicKey
    | SecretSubkey
    | ID
    | PublicSubkey
    | Unknown of int

  let detag tag =
    match tag with
    | 0 -> raise (PacketTag "A packet can't have tag 0.")
    | 1 -> SessionKey
    | 2 -> Signature
    | 5 -> SecretKey
    | 6 -> PublicKey
    | 7 -> SecretSubkey
    | 13 -> ID
    | 14 -> PublicSubkey
    | i -> Unknown i

  let name packet =
    match packet with
    | SessionKey -> "Session key packet"
    | Signature -> "Signature packet"
    | SecretKey -> "Secret Key packet"
    | PublicKey -> "Public key packet"
    | SecretSubkey -> "Secret subkey packet"
    | ID -> "Identity packet"
    | PublicSubkey -> "Public subkey packet"
    | Unknown i -> "Unknown packet (tag " ^ Int.to_string i ^ ")"

  module Header = struct
    type t =
      { packet_type : packet_type
      ; length_size : int
      ; length : int64
      ; is_new : bool }

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

  module ID = struct
    type t =
      { name : string
      ; email : string }

    let print_infos id =
      print_endline ("  name : " ^ id.name);
      print_endline ("  email : " ^ id.email)

    let decode cs (header : Header.t) =
      let length = Int64.to_int header.length in
      let packet = Cstruct.sub cs (1 + header.length_size) length in
      let id = Cstruct.to_string packet in
      let sep_id = String.split_on_char '<' id in
      let name = String.concat "<" (List.rev (List.tl (List.rev sep_id))) in
      let email = List.nth sep_id (List.length sep_id - 1) in
      {name; email = String.sub email 0 (String.length email - 1)}
  end

  type signature =
    [ `RSA of Rsa.Signature.t
    | `DSA of Dsa.Signature.t ]

  module Signature = struct
    module Subpacket = struct
      type subpacket =
        | CreationTime
        | ExpirationTime
        | ExportCertification
        | TrustSig
        | RegularExpression
        | Revocable
        | KeyExpirationTime
        | PreferredSymAlgo
        | RevocKey
        | Issuer
        | NotationData
        | PreferredHashAlgo
        | PreferredCompAlgo
        | KeyServerPref
        | PreferredKeyServer
        | PrimUserID
        | PolicyURL
        | KeyFlags
        | SignerUserID
        | ReasonRevoc
        | Feature
        | SigTarget
        | EmbeddedSig
        | IssuerFingerprint
        | PreferredAEDEDAlgo
        | UnknownSubpacket

      type t =
        | SubCreationTime of int64
        | SubExpirationTime of int64
        | SubExportCertification of bool
        | SubTrustSig of int * int
        | SubRevocable of bool
        | SubKeyExpirationTime of int64
        | SubIssuer of int64
        | SubPrimUserID of bool
        | SubSignerUserID of string
        | SubEmbeddedSig (* This type has to be moved so this can be defined. *)
        | SubIssuerFingerprint of int * Cstruct.t

      type subpacket_data =
        | Useful of t
        | Useless

      let detag tag =
        match tag with
        | 2 -> CreationTime
        | 3 -> ExpirationTime
        | 4 -> ExportCertification
        | 5 -> TrustSig
        | 6 -> RegularExpression
        | 7 -> Revocable
        | 9 -> KeyExpirationTime
        | 11 -> PreferredSymAlgo
        | 12 -> RevocKey
        | 16 -> Issuer
        | 20 -> NotationData
        | 21 -> PreferredHashAlgo
        | 22 -> PreferredCompAlgo
        | 23 -> KeyServerPref
        | 24 -> PreferredKeyServer
        | 25 -> PrimUserID
        | 26 -> PolicyURL
        | 27 -> KeyFlags
        | 28 -> SignerUserID
        | 29 -> ReasonRevoc
        | 30 -> Feature
        | 31 -> SigTarget
        | 32 -> EmbeddedSig
        | 33 -> IssuerFingerprint
        | 34 -> PreferredAEDEDAlgo
        | _ -> UnknownSubpacket

      let print_infos subpacket =
        match subpacket with
        | SubCreationTime creation_time ->
          print_endline ("   Creation time : " ^ Int64.to_string creation_time)
        | SubExpirationTime expiration_time ->
          print_endline
            ("   Expiration time : " ^ Int64.to_string expiration_time)
        | SubExportCertification flag -> (
          match flag with
          | true -> print_endline "   This signature is exportable."
          | false -> print_endline "   This signature is not exportable.")
        | SubTrustSig (depth, amount) ->
          print_endline
            ("   This signature has a trust depth of "
            ^ Int.to_string depth
            ^ " and amount of "
            ^ Int.to_string amount
            ^ ".")
        | SubRevocable flag -> (
          match flag with
          | true -> print_endline "   This signature is revocable."
          | false -> print_endline "   This signature is not revocable.")
        | SubKeyExpirationTime expiration_time ->
          print_endline
            ("   Expiration time of the subkey : "
            ^ Int64.to_string expiration_time)
        | SubIssuer key_id ->
          let id = Printf.sprintf "%Lx" key_id in
          print_endline ("   The key id is " ^ id)
        | SubPrimUserID flag -> (
          match flag with
          | true -> print_endline "   This user is the main user of this key."
          | false ->
            print_endline "   This user is not the main user of this key.")
        | SubSignerUserID id -> print_endline ("   The signer's ID is " ^ id)
        | SubEmbeddedSig -> ()
        | SubIssuerFingerprint (_, fingerprint) ->
          print_string "   The Issuer's fingerprint is : ";
          let fingerprint_str = Cstruct.to_string fingerprint in
          let fingerprint_seq = String.to_seq fingerprint_str in
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
        | CreationTime ->
          let creation_time = Cstruct.BE.get_uint32 cs 1 in
          Useful (SubCreationTime (Int64.of_int32 creation_time))
        | ExpirationTime ->
          let expiration_time = Cstruct.BE.get_uint32 cs 1 in
          Useful (SubExpirationTime (Int64.of_int32 expiration_time))
        | ExportCertification -> (
          match Cstruct.get_uint8 cs 1 with
          | 0 -> Useful (SubExportCertification false)
          | 1 -> Useful (SubExportCertification true)
          | _ -> raise (Subpacket "Exportable flag should be 0 or 1"))
        | Revocable -> (
          match Cstruct.get_uint8 cs 1 with
          | 0 -> Useful (SubRevocable false)
          | 1 -> Useful (SubRevocable true)
          | _ -> raise (Subpacket "Revocable flag should be 0 or 1"))
        | TrustSig ->
          let depth = Cstruct.get_uint8 cs 1 in
          let amount = Cstruct.get_uint8 cs 2 in
          Useful (SubTrustSig (depth, amount))
        | KeyExpirationTime ->
          let expiration_time = Cstruct.BE.get_uint32 cs 1 in
          Useful (SubExpirationTime (Int64.of_int32 expiration_time))
        | Issuer ->
          let issuer_keyid = Cstruct.BE.get_uint64 cs 1 in
          Useful (SubIssuer issuer_keyid)
        | PrimUserID -> (
          match Cstruct.get_uint8 cs 1 with
          | 0 -> Useful (SubPrimUserID false)
          | 1 -> Useful (SubPrimUserID true)
          | _ -> raise (Subpacket "Primary User ID flag should be 0 or 1"))
        | SignerUserID ->
          let str = Cstruct.to_string (Cstruct.shift cs 1) in
          Useful (SubSignerUserID str)
        | IssuerFingerprint ->
          let version = Cstruct.get_uint8 cs 1 in
          let fingerprint = Cstruct.sub cs 2 20 in
          Useful (SubIssuerFingerprint (version, fingerprint))
        | PreferredAEDEDAlgo
        | RegularExpression
        | PreferredKeyServer
        | KeyServerPref
        | NotationData
        | PreferredSymAlgo
        | PreferredCompAlgo
        | PreferredHashAlgo
        | Feature
        | PolicyURL
        | KeyFlags
        | ReasonRevoc
        | SigTarget
        | RevocKey
        | EmbeddedSig
        | UnknownSubpacket ->
          Useless
    end

    type signature_type =
      | BinaryDocSig
      | TextDocSig
      | StandaloneSig
      | GenericCertif
      | PersonaCertif
      | CasualCertif
      | PositiveCertif
      | SubkeyBinding
      | PrimkeyBinding
      | KeySig
      | KeyRevocation
      | SubkeyRevocation
      | CertifRevocation
      | TimestampSig
      | ThirdPartyConfirm

    let name sigtype =
      match sigtype with
      | BinaryDocSig -> "Signature of a binary document"
      | TextDocSig -> "Signature of a canonical text document"
      | StandaloneSig -> "Standalone signature of its own subpacket"
      | GenericCertif ->
        "Generic certification of a User ID and Public key packet"
      | PersonaCertif ->
        "Persona certification of a User ID and Public key packet"
      | CasualCertif ->
        "Casual certification of a User ID and Public key packet"
      | PositiveCertif ->
        "Positive certification of a User ID and Public key packet"
      | SubkeyBinding -> "Subkey binding signature"
      | PrimkeyBinding -> "Primary key binding signature"
      | KeySig -> "Signature directly on a key"
      | KeyRevocation -> "Key revocation signature"
      | SubkeyRevocation -> "Subkey revocation signature"
      | CertifRevocation -> "Certification revocation signature"
      | TimestampSig -> "Timestamp signature"
      | ThirdPartyConfirm -> "Third-Party confirmation signature"

    let detag tag =
      match tag with
      | 0 -> BinaryDocSig
      | 1 -> TextDocSig
      | 2 -> StandaloneSig
      | 16 -> GenericCertif
      | 17 -> PersonaCertif
      | 18 -> CasualCertif
      | 19 -> PositiveCertif
      | 24 -> SubkeyBinding
      | 25 -> PrimkeyBinding
      | 31 -> KeySig
      | 32 -> KeyRevocation
      | 40 -> SubkeyRevocation
      | 48 -> CertifRevocation
      | 64 -> TimestampSig
      | 80 -> ThirdPartyConfirm
      | _ -> raise (Signature "Incorrect tag for signature type.")

    type t =
      { version : int
      ; signature_type : signature_type
      ; public_algorithm : Algo.Public.t
      ; hash_algorithm : Algo.Hash.t
      ; signature : signature
      ; subpacket_data : Subpacket.t list }

    let print_infos signature =
      print_endline ("  Version " ^ Int.to_string signature.version);
      print_endline ("  Signature type : " ^ name signature.signature_type);
      print_endline
        ("  Public algorithm : " ^ Algo.Public.name signature.public_algorithm);
      print_endline
        ("  Hash algorithm : " ^ Algo.Hash.name signature.hash_algorithm);
      List.iter Subpacket.print_infos signature.subpacket_data

    let decode_algo (algo : Algo.Public.t) packet =
      match algo with
      | RSAEncSign
      | RSASignOnly ->
        let (_, s) = decode_mpi packet 2 in
        `RSA s
      | DSA ->
        let (r_length, r) = decode_mpi packet 2 in
        let (_, s) = decode_mpi packet (2 + r_length) in
        `DSA Dsa.Signature.{r; s}
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
      let signature = decode_algo pub_algo skipped_subpacket_data in
      { version
      ; signature_type = sigtype
      ; public_algorithm = pub_algo
      ; hash_algorithm = hash_algo
      ; signature
      ; subpacket_data }

    let decode cs (header : Header.t) =
      let length = Int64.to_int header.length in
      let packet = Cstruct.sub cs (1 + header.length_size) length in
      let version = Cstruct.get_uint8 packet 0 in
      match version with
      | 3 -> raise (Signature "Version 3 signatures not supported.")
      | 4
      | 5 ->
        decode_recent packet version
      | _ -> raise (Signature "Incorrect signature version number.")
  end

  type public_key =
    [ `RSA of Rsa.Public.t
    | `DSA of Dsa.Public.t
    | `Elgamal of Elgamal.Public.t ]

  module Publickey = struct
    type t =
      { version : int
      ; creation_time : int
      ; validity_period : int option
      ; algo : Algo.Public.t
      ; public_key : public_key }

    let print_infos public_key =
      print_endline ("  Version " ^ Int.to_string public_key.version);
      print_endline
        ("  Creation time : " ^ Int.to_string public_key.creation_time);
      print_endline ("  Algorithm : " ^ Algo.Public.name public_key.algo)

    let get_length (public_key : public_key) =
      match public_key with
      | `RSA key -> key.length
      | `DSA key -> key.length
      | `Elgamal key -> key.length

    let decode_publickey (algo : Algo.Public.t) packet =
      match algo with
      | RSAEncSign
      | RSAEncOnly
      | RSASignOnly ->
        Rsa.Public.decode packet 6
      | DSA -> Dsa.Public.decode packet 6
      | ElgaSignOnly -> Elgamal.Public.decode packet 6
      | _ -> raise (Algo "Not implemented.")

    let decode cs (header : Header.t) =
      let length = Int64.to_int header.length in
      let packet = Cstruct.sub cs (1 + header.length_size) length in
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
      let key = decode_publickey algo public_packet in
      let publickey =
        { version
        ; creation_time = Int32.to_int creation_time
        ; validity_period
        ; algo
        ; public_key = key }
      in
      publickey
  end

  type private_key =
    [ `RSA of Rsa.Private.t
    | `DSA of Dsa.Private.t
    | `Elgamal of Elgamal.Private.t ]

  module Secretkey = struct
    module S2k = struct
      type s2k_type =
        | Simple
        | Salted
        | IteratedSalted
        | Unknown

      let detag tag =
        match tag with
        | 0 -> Simple
        | 1 -> Salted
        | 3 -> IteratedSalted
        | _ -> Unknown

      let name specifier =
        match specifier with
        | Simple -> "Simple String2Key"
        | Salted -> "Salted String2Key"
        | IteratedSalted -> "Iterated&Salted String2Key"
        | Unknown -> "Unknown String2Key"

      type t =
        | Simple of Algo.Hash.t
        | Salted of Algo.Hash.t * int64
        | IteratedSalted of Algo.Hash.t * int64 * int
    end

    type t =
      { public_key : Publickey.t
      ; s2k : S2k.t option
      ; initial_vector : Cstruct.t option
      ; private_key : private_key
      ; checksum : int option
      ; hash : Cstruct.t option }

    let get_length (private_key : private_key) =
      match private_key with
      | `RSA key -> key.length
      | `DSA key -> key.length
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
      | IteratedSalted ->
        let salt_value = Cstruct.BE.get_uint64 packet 4 in
        let count = Cstruct.get_uint8 packet 12 in
        (S2k.IteratedSalted (hash_algo, salt_value, count), 13)

    let decode_secretkey packet (algo : Algo.Public.t) =
      match algo with
      | RSAEncSign
      | RSAEncOnly
      | RSASignOnly ->
        Rsa.Private.decode packet 0
      | DSA -> Dsa.Private.decode packet 0
      | ElgaSignOnly -> Elgamal.Private.decode packet 0
      | _ -> raise (Algo "Not implemented.")

    let decode_convention (public_key : Publickey.t) packet convention =
      match convention with
      | 0 ->
        let secret_packet = Cstruct.shift packet 1 in
        let secret_key = decode_secretkey secret_packet public_key.algo in
        let off = get_length secret_key in
        let checksum = Some (Cstruct.BE.get_uint16 secret_packet off) in
        { public_key
        ; s2k = None
        ; initial_vector = None
        ; private_key = secret_key
        ; checksum
        ; hash = None }
      | 254
      | 255 ->
        let sym_tag = Cstruct.get_uint8 packet 1 in
        let sym_algo = Algo.Symmetric.detag sym_tag in
        let s2k_tag = Cstruct.get_uint8 packet 2 in
        let s2k_specifier = S2k.detag s2k_tag in
        let (s2k, off) = decode_s2k packet s2k_specifier in
        let cipher_block = Algo.Symmetric.size sym_algo in
        let initial_vector = Cstruct.sub packet off cipher_block in
        let secret_packet = Cstruct.shift packet (cipher_block + off) in
        let secret_key = decode_secretkey secret_packet public_key.algo in
        let (checksum, hash) =
          if convention == 255 then
            let check = Cstruct.BE.get_uint16 packet (off + cipher_block) in
            (Some check, None)
          else
            let hash = Cstruct.sub packet (off + cipher_block) 20 in
            (None, Some hash)
        in
        { s2k = Some s2k
        ; public_key
        ; initial_vector = Some initial_vector
        ; private_key = secret_key
        ; hash
        ; checksum }
      | id ->
        let sym_algo = Algo.Symmetric.detag id in
        let s2k = S2k.Simple Algo.Hash.MD5 in
        let cipher_block = Algo.Symmetric.size sym_algo in
        let initial_vector = Cstruct.sub packet 1 cipher_block in
        let secret_packet = Cstruct.shift packet (1 + cipher_block) in
        let secret_key = decode_secretkey secret_packet public_key.algo in
        let off = get_length secret_key in
        let checksum = Some (Cstruct.BE.get_uint16 secret_packet off) in
        { s2k = Some s2k
        ; public_key
        ; initial_vector = Some initial_vector
        ; private_key = secret_key
        ; hash = None
        ; checksum }

    let decode cs (header : Header.t) =
      let public_key = Publickey.decode cs header in
      let off = 7 + Publickey.get_length public_key.public_key in
      let _secret_packet = Cstruct.shift cs (header.length_size + off) in
      let secret_packet =
        Cstruct.sub _secret_packet 0 (Int64.to_int header.length)
      in
      let convention = Cstruct.get_uint8 secret_packet 0 in
      decode_convention public_key secret_packet convention
  end

  type t =
    { header : Header.t
    ; packet :
        [ `ID of ID.t
        | `Secretkey of Secretkey.t
        | `Publickey of Publickey.t
        | `Signature of Signature.t
        | `Secretsubkey of Secretkey.t
        | `Publicsubkey of Publickey.t ] }

  let advance_cs cs (header : Header.t) =
    let real_size = header.length_size + Int64.to_int header.length in
    Cstruct.shift cs (real_size + 1)

  let decode_packet cs (header : Header.t) =
    let packet =
      match header.packet_type with
      | ID -> `ID (ID.decode cs header)
      | SecretKey -> `Secretkey (Secretkey.decode cs header)
      | PublicKey -> `Publickey (Publickey.decode cs header)
      | Signature -> `Signature (Signature.decode cs header)
      | SecretSubkey -> `Secretsubkey (Secretkey.decode cs header)
      | PublicSubkey -> `Publicsubkey (Publickey.decode cs header)
      | _ -> raise (Packet ("Not implemented : " ^ name header.packet_type))
    in
    {header; packet}

  let rec decode_rec cs header packet_list =
    try
      let next_cs = advance_cs cs header in
      let next_header = Header.decode next_cs in
      let packet = decode_packet next_cs next_header in
      decode_rec next_cs next_header (packet :: packet_list)
    with
    | Invalid_argument _ -> List.rev packet_list

  let print_infos packet =
    Header.print_infos packet.header;
    (match packet.packet with
    | `ID id -> ID.print_infos id
    | `Secretkey secret_key -> Publickey.print_infos secret_key.public_key
    | `Publickey public_key -> Publickey.print_infos public_key
    | `Signature signature -> Signature.print_infos signature
    | `Secretsubkey secret_subkey ->
      Publickey.print_infos secret_subkey.public_key
    | `Publicsubkey public_subkey -> Publickey.print_infos public_subkey);
    print_newline ()

  let decode cs =
    let header = Header.decode cs in
    let packet = decode_packet cs header in
    decode_rec cs header [packet]
end

(* moves after the armoring *)

let rec check_offset cs i j =
  let first_val = Cstruct.get_uint8 cs i in
  match first_val with
  | 10 when j == 1 -> i + 1
  | 10 -> check_offset cs (i + 1) (j + 1)
  | 58 -> check_offset cs (i + 1) 0
  | _ -> check_offset cs (i + 1) j

(* I copied this from pem_utils.ml (host-scanner) v *)

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

(*************************************)

let decode_base64 cs =
  let off = check_offset cs 0 0 in
  let str = Cstruct.to_string ~off cs in
  let decoded_str = relaxed_base64_rfc2045_of_string str in
  let decoded_cs = Cstruct.of_string decoded_str in
  let res = Packet.decode decoded_cs in
  List.iter Packet.print_infos res

let decode cs =
  let res = Packet.decode cs in
  List.iter Packet.print_infos res
