(** Parsers for RSA and EC Card Verifiable Certificate key formats *)

module RSA :
sig
  module Public :
  sig
    type t =
      { n: Z.t
      ; e: Z.t
      }
    [@@deriving ord,eq,yojson,eq,show,bin_io]

    val decode : Cstruct.t -> (t, string) Result.result
  end
end

module EC :
sig
  module Public :
  sig
    type t =
      { modulus : Z.t
      ; coefficient_a : Cstruct.t
      ; coefficient_b : Cstruct.t
      ; base_point_g : Cstruct.t
      ; base_point_r_order : Z.t
      ; public_point_y : Cstruct.t
      ; cofactor_f : Z.t
      }
    [@@deriving ord,eq,yojson,eq,show,bin_io]

    val decode : Cstruct.t -> (t, string) Result.result
  end
end
