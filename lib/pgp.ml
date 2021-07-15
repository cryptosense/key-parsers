exception LengthBlock of string
exception PacketTag of string

type packet_type =
    |SessionKey
    |Signature
    |SecretKey
    |PublicKey
    |SecretSubkey
    |ID
    |PublicSubkey
    |Untreated

let detag_packet tag =
  match tag with
  | 0 -> raise (PacketTag "A packet can't have tag 0.")
  | 1 ->  SessionKey
  | 2 -> Signature
  | 5 -> SecretKey
  | 6 -> PublicKey
  | 7 -> SecretSubkey
  | 13 -> ID
  | 14 -> PublicSubkey
  | _ -> Untreated
   

let name_packet packet =
  match packet with
  | SessionKey -> "Session key packet"
  | Signature -> "Signature packet"
  | SecretKey -> "Secret Key packet"
  | PublicKey -> "Public key packet"
  | SecretSubkey -> "Secret subkey packet"
  | ID -> "Identity packet"
  | PublicSubkey -> "Public subkey packet"
  | Untreated -> "Untreated packet"
  

type header = {
  name : packet_type;
  length_size : int;
  length : int64;
  is_new : bool;
}

(* moves after the armoring *)

let rec check_offset cs i j =
  let first_val = Cstruct.get_uint8 cs i in
  match first_val with
  | 10 when j == 1 -> i+1
  | 10 -> check_offset cs (i+1) (j+1)
  | 58 -> check_offset cs (i+1) 0
  | _  -> check_offset cs (i+1) j

(* Checks if the packet has a old or new type of header *)

let is_new_type header =
  if header >= 192 then
    true
  else
    false

let get_tag header =
  if  is_new_type header then
    header - 192
  else
    (header-128)/4

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

let get_old_length_size length_tag =
  match length_tag with
  | 0 -> 1
  | 1 -> 2
  | 2 -> 4
  | 3 -> raise (LengthBlock "Not implemented.")
  | _ -> raise (LengthBlock "Length block doesn't have a correct value.")


let get_old_length cs header_code =
  let length_size = get_old_length_size (header_code mod 4) in
  let length = match length_size with
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
    let length = 192 + second_octet + (256 * (first_octet-192)) in
    (2, Int64.of_int length)
  else if first_octet < 255 then
    raise (LengthBlock "Partial body length are not treated.")
  else
    let length = Cstruct.BE.get_uint32 cs 2 in
    (5, Int64.of_int32 length)
  

let decode_header cs =
  let header_code = Cstruct.get_uint8 cs 0 in
  let tag = get_tag header_code in
  let (length_size,length) =
  if is_new_type header_code then
      get_new_length cs
    else
      get_old_length cs header_code
  in
  { name = detag_packet tag;
    length_size = length_size;
    length = length;
    is_new = is_new_type header_code;
  }
    
let print_infos header =
  print_string
    (match header.is_new with
    | true -> "New type of "
    | false -> "Old type of ");
  print_string ((name_packet header.name) ^ " of length ");
  print_string (Int64.to_string header.length);
  print_string " (+";
  print_int header.length_size;
  print_string " octets for the size of the header).\n"

(* deletes the first packet of the cstruct *)

let advance_cs cs header =
  let real_size = header.length_size + (Int64.to_int header.length) in
  Cstruct.shift cs (real_size+1)

let rec decode_exn cs header =
  try
    let next_cs = advance_cs cs header in
    let next_header = decode_header next_cs in
    print_infos next_header;
    decode_exn next_cs next_header
  with
  | Invalid_argument _ -> ()

let decode_base64 cs =
  let off = check_offset cs 0 0 in
  let str = Cstruct.to_string ~off:off cs in
  let decoded_str = relaxed_base64_rfc2045_of_string str in
    let decoded_cs = Cstruct.of_string decoded_str in
  let header = decode_header decoded_cs in
  print_infos header;
  decode_exn decoded_cs header

let decode cs =
  let header = decode_header cs in
  print_infos header;
  decode_exn cs header
