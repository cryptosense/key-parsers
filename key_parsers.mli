module RSA :
sig
  module Public :
  sig
    type t = {
      n: Z.t;
      e: Z.t;
    }

    val grammar : t Asn.t

    val encode : t -> Cstruct.t
    val decode : Cstruct.t -> t
  end

  module Private :
  sig
    type other_prime = {
        r: Z.t;
        d: Z.t;
        t: Z.t;
    }

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

    val other_prime_grammar : other_prime Asn.t
    val grammar : t Asn.t

    val encode : t -> Cstruct.t
    val decode : Cstruct.t -> t
  end
end

module DSA :
sig
  module Params :
  sig
    type t = {
      p: Z.t;
      q: Z.t;
      g: Z.t;
    }

    val grammar : t Asn.t

    val encode : t -> Cstruct.t
    val decode : Cstruct.t -> t
  end

  module Public :
  sig
    type t = Z.t

    val grammar : t Asn.t

    val encode : t -> Cstruct.t
    val decode : Cstruct.t -> t
  end

  module Private :
  sig
    type t = Z.t

    val grammar : t Asn.t

    val encode : t -> Cstruct.t
    val decode : Cstruct.t -> t
  end
end

module X509 :
sig
  type t =
    [ `RSA of RSA.Public.t
    | `DSA of DSA.Params.t * DSA.Public.t
    | `EC of Asn.OID.t * Cstruct.t
    | `Unknown of Asn.OID.t
    ]

  val grammar : t Asn.t

  val encode : t -> Cstruct.t
  val decode : Cstruct.t -> t
end

module PKCS8 :
sig
  type t =
    [ `RSA of RSA.Private.t
    | `DSA of DSA.Params.t * DSA.Private.t
    | `EC of Asn.OID.t * Cstruct.t
    | `Unknown of Asn.OID.t
    ]

  val grammar : t Asn.t

  val encode : t -> Cstruct.t
  val decode : Cstruct.t -> t

  val encode_rsa : RSA.Private.t -> Cstruct.t
  val decode_rsa : Cstruct.t -> RSA.Private.t
end
