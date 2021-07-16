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

type packet_type =
  | SessionKey
  | Signature
  | SecretKey
  | PublicKey
  | SecretSubkey
  | ID
  | PublicSubkey
  | Unknown

let detag_packet tag =
  match tag with
  | 0 -> raise (PacketTag "A packet can't have tag 0.")
  | 1 -> SessionKey
  | 2 -> Signature
  | 5 -> SecretKey
  | 6 -> PublicKey
  | 7 -> SecretSubkey
  | 13 -> ID
  | 14 -> PublicSubkey
  | _ -> Unknown

let name_packet packet =
  match packet with
  | SessionKey -> "Session key packet"
  | Signature -> "Signature packet"
  | SecretKey -> "Secret Key packet"
  | PublicKey -> "Public key packet"
  | SecretSubkey -> "Secret subkey packet"
  | ID -> "Identity packet"
  | PublicSubkey -> "Public subkey packet"
  | Unknown -> "Unknown packet"

type pub_algorithm =
  | RSAEncSign
  | RSAEncOnly
  | RSASignOnly
  | ElgaSignOnly
  | DSA
  | EC
  | ECDSA

let match_pub_algo tag =
  match tag with
  | 1 -> RSAEncSign
  | 2 -> RSAEncOnly
  | 3 -> RSASignOnly
  | 16 -> ElgaSignOnly
  | 17 -> DSA
  | 18 -> EC
  | 19 -> ECDSA
  | _ -> raise (Algo "Algorithm not found.")

let name_pub_algorithm algo =
  match algo with
  | RSAEncSign -> "RSA Encryption & Signature"
  | RSAEncOnly -> "RSA Encryption only"
  | RSASignOnly -> "RSA Signature only"
  | ElgaSignOnly -> "Elgamal Signature only"
  | DSA -> "DSA"
  | EC -> "EC"
  | ECDSA -> "EC DSA"

type hash_algorithm =
  | MD5
  | SHA1
  | RIPE_MD160
  | SHA2_256
  | SHA2_384
  | SHA2_512
  | SHA2_224
  | SHA3_256
  | SHA3_512

let name_hash_algorithm algo =
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

let match_hash_algo tag =
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

let sigtype_to_string sigtype =
  match sigtype with
  | BinaryDocSig -> "Signature of a binary document"
  | TextDocSig -> "Signature of a canonical text document"
  | StandaloneSig -> "Standalone signature of its own subpacket"
  | GenericCertif -> "Generic certification of a User ID and Public key packet"
  | PersonaCertif -> "Persona certification of a User ID and Public key packet"
  | CasualCertif -> "Casual certification of a User ID and Public key packet"
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

let match_sigtype tag =
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

type subpacket_sigtype =
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

type subpacket_data =
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

let match_subpacket_sig_tag tag =
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

module Rsa = struct
  module Public = struct
    type t =
      { n : Derivable.Z.t
      ; e : Derivable.Z.t }
    [@@deriving ord, eq, show]
  end

  module Private = struct
    type t =
      { e : Derivable.Z.t
      ; d : Derivable.Z.t
      ; p : Derivable.Z.t
      ; q : Derivable.Z.t }
  end
  [@@deriving ord, eq, show]

  module Signature = struct
    type t = Derivable.Z.t
  end
  [@@deriving ord, eq, show]
end

module Dsa = struct
  module Params = struct
    type t =
      { p : Derivable.Z.t
      ; q : Derivable.Z.t
      ; g : Derivable.Z.t }
  end
  [@@deriving ord, eq, show]

  module Public = struct
    type t = Derivable.Z.t
  end
  [@@deriving ord, eq, show]

  module Private = struct
    type t = Derivable.Z.t
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
      ; y : Derivable.Z.t }
  end
  [@@deriving ord, eq, show]

  module Private = struct
    type t = Derivable.Z.t
  end
  [@@deriving ord, eq, show]
end

type _subpacket_data =
  | Useful of subpacket_data
  | Useless

module Packet = struct
  module Header = struct
    type t =
      { packet_type : packet_type
      ; length_size : int
      ; length : int64
      ; is_new : bool }
  end

  module ID = struct
    type t =
      { name : string
      ; email : string }
  end

  type signature =
    [ `RSA of Rsa.Signature.t
    | `DSA of Dsa.Signature.t ]

  module Signature = struct
    module Header = struct
      type t =
        { length_size : int
        ; length : int64 }
    end

    type t =
      { version : int
      ; signature_type : signature_type
      ; public_algorithm : pub_algorithm
      ; hash_algorithm : hash_algorithm
      ; signature : signature
      ; subpacket_data : subpacket_data list }
  end

  type public_key =
    [ `RSA of Rsa.Public.t
    | `DSA of Dsa.Params.t * Dsa.Public.t
    | `Elgamal of Elgamal.Public.t ]

  module Publickey = struct
    type t =
      { version : int
      ; creation_time : int
      ; algo : pub_algorithm
      ; public_key : public_key }
  end

  type t =
    { header : Header.t
    ; packet :
        [ `ID of ID.t
        | `Publickey of Publickey.t
        | `Signature of Signature.t
        | `Publicsubkey of Publickey.t ] }
end

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

let decode_header cs =
  let header_code = Cstruct.get_uint8 cs 0 in
  let tag = get_tag header_code in
  let (length_size, length) =
    if is_new_type header_code then
      get_new_length cs
    else
      get_old_length cs header_code
  in
  Packet.Header.
    { packet_type = detag_packet tag
    ; length_size
    ; length
    ; is_new = is_new_type header_code }

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

(* deletes the first packet of the cstruct *)

let advance_cs cs (header : Packet.Header.t) =
  let real_size = header.length_size + Int64.to_int header.length in
  Cstruct.shift cs (real_size + 1)

let decode_ID cs (header : Packet.Header.t) =
  let length = Int64.to_int header.length in
  let packet = Cstruct.sub cs (1 + header.length_size) length in
  let id = Cstruct.to_string packet in
  let sep_id = String.split_on_char '<' id in
  let name = String.concat "<" (List.rev (List.tl (List.rev sep_id))) in
  let email = List.nth sep_id (List.length sep_id - 1) in
  Packet.ID.{name; email = String.sub email 0 (String.length email - 1)}

let decode_mpi cs off =
  let bit_length = Cstruct.BE.get_uint16 cs off in
  let length = (bit_length / 8) + min 1 (bit_length mod 8) in
  (length, get_z_be cs (2 + off) length)

let decode_rsa packet =
  let (n_length, n) = decode_mpi packet 6 in
  let (_, e) = decode_mpi packet (n_length + 8) in
  let public_key = Rsa.Public.{n; e} in
  `RSA public_key

let decode_dsa packet =
  let (p_length, p) = decode_mpi packet 6 in
  let (q_length, q) = decode_mpi packet (p_length + 8) in
  let (g_length, g) = decode_mpi packet (p_length + q_length + 10) in
  let (_, y) = decode_mpi packet (p_length + q_length + g_length + 12) in
  let params = Dsa.Params.{p; q; g} in
  `DSA (params, y)

let decode_elgamal packet =
  let (p_length, p) = decode_mpi packet 6 in
  let (g_length, g) = decode_mpi packet (8 + p_length) in
  let (_, y) = decode_mpi packet (10 + p_length + g_length) in
  let public_key = Elgamal.Public.{p; g; y} in
  `Elgamal public_key

let decode_publickey algo packet =
  match algo with
  | RSAEncSign
  | RSAEncOnly
  | RSASignOnly ->
    decode_rsa packet
  | DSA -> decode_dsa packet
  | ElgaSignOnly -> decode_elgamal packet
  | _ -> raise (Algo "Not implemented.")

let decode_publickey_packet cs (header : Packet.Header.t) =
  let length = Int64.to_int header.length in
  let packet = Cstruct.sub cs (1 + header.length_size) length in
  let version = Cstruct.get_uint8 packet 0 in
  let creation_time = Cstruct.BE.get_uint32 packet 1 in
  let algo = match_pub_algo (Cstruct.get_uint8 packet 5) in
  let key = decode_publickey algo packet in
  let publickey =
    Packet.Publickey.
      { version
      ; creation_time = Int32.to_int creation_time
      ; algo
      ; public_key = key }
  in
  publickey

let decode_signature packet algo =
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

let subpacket_header_length cs =
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

let decode_subpacket cs =
  let tag = Cstruct.get_uint8 cs 0 in
  let subpacket_sigtype = match_subpacket_sig_tag tag in
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
    let fingerprint = Cstruct.shift cs 2 in
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

let rec signature_data cs data length =
  match length with
  | 0 -> data
  | _ -> (
    let (header_length, subpacket_length) = subpacket_header_length cs in
    let subcs = Cstruct.shift cs header_length in
    let subpacket_data = decode_subpacket subcs in
    let cs_rec = Cstruct.shift subcs (Int64.to_int subpacket_length) in
    match subpacket_data with
    | Useful sub_data ->
      signature_data cs_rec (sub_data :: data)
        (length - header_length - Int64.to_int subpacket_length)
    | Useless ->
      signature_data cs_rec data
        (length - header_length - Int64.to_int subpacket_length))

let decode_recent_signature packet version =
  let sigtype_tag = Cstruct.get_uint8 packet 1 in
  let sigtype = match_sigtype sigtype_tag in
  let pub_algo_tag = Cstruct.get_uint8 packet 2 in
  let pub_algo = match_pub_algo pub_algo_tag in
  let hash_algo_tag = Cstruct.get_uint8 packet 3 in
  let hash_algo = match_hash_algo hash_algo_tag in
  let hashed_subdata_length = Cstruct.BE.get_uint16 packet 4 in
  let skipped_hashed_data = Cstruct.shift packet (6 + hashed_subdata_length) in
  let unhashed_data_length = Cstruct.BE.get_uint16 skipped_hashed_data 0 in
  let hashed_cs = Cstruct.sub packet 6 hashed_subdata_length in
  let unhashed_cs = Cstruct.sub skipped_hashed_data 2 unhashed_data_length in
  let subpacket_cs = Cstruct.concat [hashed_cs; unhashed_cs] in
  let subpacket_length = Cstruct.length subpacket_cs in
  let subpacket_data = signature_data subpacket_cs [] subpacket_length in
  let skipped_subpacket_data =
    Cstruct.shift skipped_hashed_data (2 + unhashed_data_length)
  in
  let signature = decode_signature skipped_subpacket_data pub_algo in
  Packet.Signature.
    { version
    ; signature_type = sigtype
    ; public_algorithm = pub_algo
    ; hash_algorithm = hash_algo
    ; signature
    ; subpacket_data }

let decode_signature_packet cs (header : Packet.Header.t) =
  let length = Int64.to_int header.length in
  let packet = Cstruct.sub cs (1 + header.length_size) length in
  let version = Cstruct.get_uint8 packet 0 in
  match version with
  | 3 -> raise (Signature "Version 3 signatures not supported.")
  | 4
  | 5 ->
    decode_recent_signature packet version
  | _ -> raise (Signature "Incorrect signature version number.")

let decode_packet cs (header : Packet.Header.t) =
  let packet =
    match header.packet_type with
    | ID -> `ID (decode_ID cs header)
    | PublicKey -> `Publickey (decode_publickey_packet cs header)
    | Signature -> `Signature (decode_signature_packet cs header)
    | PublicSubkey -> `Publicsubkey (decode_publickey_packet cs header)
    | _ -> raise (Packet "Not implemented.")
  in
  Packet.{header; packet}

let rec decode_exn cs header packet_list =
  try
    let next_cs = advance_cs cs header in
    let next_header = decode_header next_cs in
    let packet = decode_packet next_cs next_header in
    decode_exn next_cs next_header (packet :: packet_list)
  with
  | Invalid_argument _ -> List.rev packet_list

let print_infos_header (header : Packet.Header.t) =
  print_string
    (match header.is_new with
    | true -> "New type of "
    | false -> "Old type of ");
  print_string (name_packet header.packet_type ^ " of length ");
  print_string (Int64.to_string header.length);
  print_string " (+";
  print_int header.length_size;
  print_string " octets for the size of the header).\n"

let print_id_packet (id : Packet.ID.t) =
  print_endline ("  name : " ^ id.name);
  print_endline ("  email : " ^ id.email)

let print_publickey_packet (public_key : Packet.Publickey.t) =
  print_endline ("  Version " ^ Int.to_string public_key.version);
  print_endline ("  Creation time : " ^ Int.to_string public_key.creation_time);
  print_endline ("  Algorithm : " ^ name_pub_algorithm public_key.algo)

let print_signature_subpacket (subpacket : subpacket_data) =
  match subpacket with
  | SubCreationTime creation_time ->
    print_endline ("   Creation time : " ^ Int64.to_string creation_time)
  | SubExpirationTime expiration_time ->
    print_endline ("   Expiration time : " ^ Int64.to_string expiration_time)
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
      ("   Expiration time of the subkey : " ^ Int64.to_string expiration_time)
  | SubIssuer key_id ->
    let id = Printf.sprintf "%Lx" key_id in
    print_endline ("   The key id is " ^ id)
  | SubPrimUserID flag -> (
    match flag with
    | true -> print_endline "   This user is the main user of this key."
    | false -> print_endline "   This user is not the main user of this key.")
  | SubSignerUserID id -> print_endline ("   The signer's ID is " ^ id)
  | SubEmbeddedSig -> ()
  | SubIssuerFingerprint (_, fingerprint) ->
    print_endline
      ("   The Issuer's fingerprint is " ^ Cstruct.to_string fingerprint)

let print_signature_packet (signature : Packet.Signature.t) =
  print_endline ("  Version " ^ Int.to_string signature.version);
  print_endline
    ("  Signature type : " ^ sigtype_to_string signature.signature_type);
  print_endline
    ("  Public algorithm : " ^ name_pub_algorithm signature.public_algorithm);
  print_endline
    ("  Hash algorithm : " ^ name_hash_algorithm signature.hash_algorithm);
  List.iter print_signature_subpacket signature.subpacket_data

let print_infos (packet : Packet.t) =
  print_infos_header packet.header;
  (match packet.packet with
  | `ID id -> print_id_packet id
  | `Publickey public_key -> print_publickey_packet public_key
  | `Signature signature -> print_signature_packet signature
  | `Publicsubkey public_subkey -> print_publickey_packet public_subkey);
  print_newline ()

let decode_base64 cs =
  let off = check_offset cs 0 0 in
  let str = Cstruct.to_string ~off cs in
  let decoded_str = relaxed_base64_rfc2045_of_string str in
  let decoded_cs = Cstruct.of_string decoded_str in
  let header = decode_header decoded_cs in
  let packet = decode_packet decoded_cs header in
  let res = decode_exn decoded_cs header [packet] in
  List.iter print_infos res

let decode cs =
  let header = decode_header cs in
  let packet = decode_packet cs header in
  let res = decode_exn cs header [packet] in
  List.iter print_infos res
