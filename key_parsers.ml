module RSA =
struct
  module Public =
  struct
    type t = {
      n: Z.t;
      e: Z.t;
    }

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
      let t, left = decode_exn (codec ber grammar) key in
      if Cstruct.len left = 0 then t
      else parse_error "PKCS1: RSA private key with non empty leftover"
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
      let t, left = decode_exn (codec ber grammar) key in
      if Cstruct.len left = 0 then t
      else parse_error "DSA: Params with non empty leftover"
  end

  module Public =
  struct
    type t = Z.t

    let grammar = Asn.integer

    let encode = Asn.(encode (codec der grammar))

    let decode key =
      let open Asn in
      let t, left = decode_exn (codec ber grammar) key in
      if Cstruct.len left = 0 then t
      else parse_error "DSA: public key with non empty leftover"
  end

  module Private =
  struct
    type t = Z.t

    let grammar = Asn.integer

    let encode = Asn.(encode (codec der grammar))

    let decode key =
      let open Asn in
      let t, left = decode_exn (codec ber grammar) key in
      if Cstruct.len left = 0 then t
      else parse_error "DSA: private key with non empty leftover"
  end
end

module Algo =
struct
  let rsa_oid = Asn.OID.of_string "1.2.840.113549.1.1.1"
  let dsa_oid = Asn.OID.of_string "1.2.840.10040.4.1"
  let ec_oid = Asn.OID.of_string "1.2.840.10045.2.1"

  type t =
    | DSA
    | RSA
    | EC
    | Unknown of Asn.OID.t

  let grammar =
    let open Asn in
    let f = function
      | oid when oid = rsa_oid -> RSA
      | oid when oid = dsa_oid -> DSA
      | oid when oid = ec_oid -> EC
      | oid ->  Unknown oid in
    let g = function
      | RSA -> rsa_oid
      | DSA -> dsa_oid
      | EC -> ec_oid
      | Unknown oid -> oid in
    map f g oid
end

module Params =
struct
  type t =
    | Null
    | Oid of Asn.OID.t
    | DSA of DSA.Params.t

  let grammar =
    let open Asn in
    let f = function
      | `C1 () -> Null
      | `C2 oid -> Oid oid
      | `C3 dsa_params -> DSA dsa_params in
    let g = function
      | Null -> `C1 ()
      | Oid oid -> `C2 oid
      | DSA dsa_params -> `C3 dsa_params in
    map f g @@ choice3 null oid DSA.Params.grammar
end

module Algorithm_identifier =
struct
  type t =
    | RSA
    | EC of Asn.OID.t
    | DSA of DSA.Params.t
    | Unknown of Asn.OID.t * Params.t

  let grammar =
    let open Asn in
    let f = function
      | Algo.RSA, Params.Null -> RSA
      | Algo.RSA, _ ->
          parse_error "Algorithm_identifier: RSA params should be null"
      | Algo.DSA, Params.DSA params -> DSA params
      | Algo.DSA, _ ->
          invalid_arg "Algorithm_identifier: invalid DSA params"
      | Algo.EC, Params.Oid oid -> EC oid
      | Algo.EC, _ ->
          parse_error "Algorithm_identifier: EC params should be an oid"
      | Algo.Unknown oid, (Params.Oid _ as params)
      | Algo.Unknown oid, (Params.DSA _ as params)
      | Algo.Unknown oid, (Params.Null as params) -> Unknown (oid, params) in
    let g = function
      | RSA -> Algo.RSA, Params.Null
      | DSA params -> Algo.DSA, Params.DSA params
      | EC curve -> Algo.EC, Params.Oid curve
      | Unknown (algo, params) -> Algo.Unknown algo, params in
    map f g @@ sequence2
      (required ~label:"algorithm" Algo.grammar)
      (required ~label:"params" Params.grammar)
end

module X509 =
struct
  type t =
    [ `RSA of RSA.Public.t
    | `DSA of DSA.Params.t * DSA.Public.t
    | `EC of Asn.OID.t * Cstruct.t
    | `Unknown of Asn.OID.t
    ]

  let grammar =
    let open Asn in
    let open Algorithm_identifier in
    let f = function
      | RSA, bit_string -> `RSA (RSA.Public.decode bit_string)
      | DSA params, bit_string -> `DSA (params, DSA.Public.decode bit_string)
      | EC curve, bit_string -> `EC (curve, bit_string)
      | Unknown (oid, _), _ -> `Unknown oid in
    let g = function
      | `RSA key -> (RSA, RSA.Public.encode key)
      | `DSA (params, key) -> (DSA params, DSA.Public.encode key)
      | `EC (curve, key) -> (EC curve, key)
      | `Unknown oid ->
          invalid_arg "X509: cannot encode unknown key type" in
    map f g @@ sequence2
      (required ~label:"alogrithm" Algorithm_identifier.grammar)
      (required ~label:"subjectPublicKey" bit_string_cs)

  let encode = Asn.(encode (codec der grammar))

  let decode key =
    let open Asn in
    let t, left = decode_exn (codec ber grammar) key in
    if Cstruct.len left = 0 then t
    else parse_error "X509: key with non empty leftover"
end

module PKCS8 =
struct
  type t =
    [ `RSA of RSA.Private.t
    | `DSA of DSA.Params.t * DSA.Private.t
    | `EC of Asn.OID.t * Cstruct.t
    | `Unknown of Asn.OID.t
    ]

  let grammar =
    let open Asn in
    let open Algorithm_identifier in
    let f (version, alg, key, attributes) =
      if version = 0 then
        match alg, key, attributes with
          | RSA, bit_string, _ -> `RSA (RSA.Private.decode bit_string)
          | DSA params, bit_string, _ -> `DSA (params, DSA.Private.decode bit_string)
          | EC curve, bit_string, _ -> `EC (curve, bit_string)
          | Unknown (oid, _), _ , _ -> `Unknown oid
      else
        parse_error @@
        Printf.sprintf "PKCS8: version %d not supported" version in
    let g = function
      | `RSA key -> (0, RSA, RSA.Private.encode key, None)
      | `DSA (params, key) -> (0, DSA params, DSA.Private.encode key, None)
      | `EC (curve, key) -> (0, EC curve, key, None)
      | `Unknown _ ->
          invalid_arg "PKCS8: cannot encode unknown key type" in
    map f g @@ sequence4
      (required ~label:"version" int)
      (required ~label:"privateKeyAlgorithm" Algorithm_identifier.grammar)
      (required ~label:"privateKey" octet_string)
      (optional ~label:"attributes" null)

  let encode = Asn.(encode (codec der grammar))

  let decode key =
    let open Asn in
    let t, left = decode_exn (codec ber grammar) key in
    if Cstruct.len left = 0 then t
    else parse_error "PKCS8: key with non empty leftover"

  let encode_rsa key = encode (`RSA key)

  let decode_rsa key =
    match decode key with
    | `RSA key -> key
    | _ -> invalid_arg "PKCS8: Not a RSA key"
end
