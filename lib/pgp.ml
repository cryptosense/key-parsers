exception LengthBlock of string
exception PacketTag of string
exception Algo of string
exception Packet of string

(*from ltpa.ml*)

let get_z_be cs off len =
  let r = ref Z.zero in
  let base = Z.of_int 0x100 in
  for i = off to off + len - 1 do
    r := Z.add (Z.mul base !r) @@ Z.of_int @@ Cstruct.get_uint8 cs i
  done;
  !r

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


type pub_algorithm =
  |RSAEncSign
  |RSAEncOnly
  |RSASignOnly
  |ElgaSignOnly
  |DSA
  |EC
  |ECDSA   

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

module Rsa =
struct
  module Public =
  struct
    type t = {
      n: Derivable.Z.t;
      e: Derivable.Z.t;
    }
    [@@deriving ord,eq,show]
  end
end

module Dsa =
struct
  module Params =
  struct
    type t = {
      p :  Derivable.Z.t;
      q :  Derivable.Z.t;
      g : Derivable.Z.t;
    }
  end
  
  module Public =
  struct
    type t = Derivable.Z.t
  end
  
end
      

module Packet =
struct
  module Header =
  struct
    type t = {
      packet_type : packet_type;
      length_size : int;
      length : int64;
      is_new : bool;
    }
  end
  
  module ID =
  struct
    type t = {
      id : string;
    }
  end

  module Signature =
  struct
    type t = unit
  end
  
  type public_key =
    [`RSA of Rsa.Public.t
    |`DSA of Dsa.Params.t * Dsa.Public.t
    ]
  
  module Publickey =
  struct
    type t = {
      version : int;
      creation_time : int;
      algo : pub_algorithm;
      public_key : public_key;
    }
  end

  module Publicsubkey =
  struct
    type t = unit
  end

  type t = {
    header : Header.t;
    packet : [ `ID of ID.t
             | `Publickey of Publickey.t
             | `Signature of Signature.t
             | `Publicsubkey of Publicsubkey.t
             ];
  }
end


let is_new_type header_code =
  if header_code >= 192 then
    true
  else
    false

let get_tag header_code =
  if  is_new_type header_code then
    header_code - 192
  else
    (header_code-128)/4

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
    



let print_infos (header:Packet.Header.t) =
  print_string
    (match header.is_new with
     | true -> "New type of "
     | false -> "Old type of ");
  print_string ((name_packet header.packet_type) ^ " of length ");
  print_string (Int64.to_string header.length);
  print_string " (+";
  print_int header.length_size;
  print_string " octets for the size of the header).\n"
    
let decode_header cs =
  let header_code = Cstruct.get_uint8 cs 0 in
  let tag = get_tag header_code in
  let (length_size,length) =
    if is_new_type header_code then
      get_new_length cs
    else
      get_old_length cs header_code
  in
  Packet.Header.{
    packet_type = detag_packet tag;
    length_size = length_size;
    length = length;
    is_new = is_new_type header_code;
  }
    
(* moves after the armoring *)
    
let rec check_offset cs i j =
  let first_val = Cstruct.get_uint8 cs i in
  match first_val with
  | 10 when j == 1 -> i+1
  | 10 -> check_offset cs (i+1) (j+1)
  | 58 -> check_offset cs (i+1) 0
  | _  -> check_offset cs (i+1) j


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

let advance_cs cs (header:Packet.Header.t) =
  let real_size = header.length_size + (Int64.to_int header.length) in
  Cstruct.shift cs (real_size+1)

let decode_ID cs (header:Packet.Header.t) =
  let length = Int64.to_int header.length in
  let packet = Cstruct.sub cs (1+header.length_size) length in
  Packet.ID.{id = Cstruct.to_string packet }

let decode_mpi cs off =
  let bit_length = Cstruct.BE.get_uint16 cs off in
  let length = (bit_length)/8 + (bit_length mod 2) in
  (length, get_z_be cs (2+off) length)
               

let decode_rsa packet =
  let (n_length,n) = decode_mpi packet 6 in
  let (_,e) = decode_mpi packet (n_length+8) in
  let public_key = Rsa.Public.{ n=n; e=e;} in
  `RSA public_key

let decode_dsa packet =
  let (p_length,p) = decode_mpi packet 6 in
  let (q_length,q) = decode_mpi packet (p_length+8) in
  let (g_length,g) = decode_mpi packet (p_length+q_length+10) in
  let off = p_length + q_length + g_length + 12 in
  let (_,y) = decode_mpi packet off in
  let params = Dsa.Params.{
      p = p;
      q = q;
      g = g;
    } in
  `DSA (params,y)
  

let decode_publickey algo packet =
  match algo with
  | RSAEncSign | RSAEncOnly | RSASignOnly -> decode_rsa packet
  | DSA -> decode_dsa packet
  | _ -> raise (Algo "Not implemented.")

let decode_publickey_packet cs (header:Packet.Header.t) =
  let length = Int64.to_int header.length in
  let packet = Cstruct.sub cs (1+header.length_size) length in
  let version = Cstruct.get_uint8 packet 0 in
  let creation_time = Cstruct.BE.get_uint32 packet 1 in
  let algo = match_pub_algo (Cstruct.get_uint8 packet 5) in
  let key = decode_publickey algo packet in
  let publickey = Packet.Publickey.{
      version = version;
      creation_time = Int32.to_int creation_time;
      algo = algo;
      public_key = key;
    } in
  publickey


let decode_packet cs (header:Packet.Header.t) =
  let packet =
    match header.packet_type with
    |ID -> `ID (decode_ID cs header)
    |PublicKey -> `Publickey (decode_publickey_packet cs header)
    |Signature -> `Signature ()
    |PublicSubkey -> `Publicsubkey ()
    |_ -> raise (Packet "Not implemented")
  in Packet.{
      header = header;
      packet = packet;
  }
  
let rec decode_exn cs header =
  try
    let next_cs = advance_cs cs header in
    let next_header = decode_header next_cs in
    let packet = decode_packet next_cs next_header in
    print_infos packet.header;
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
  let packet = decode_packet cs header in
  print_infos packet.header;
  decode_exn cs header
