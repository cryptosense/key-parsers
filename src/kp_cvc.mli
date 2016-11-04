module RSA :
sig
  module Public :
  sig
    type t =
      { n: Z.t
      ; e: Z.t
      }
    [@@deriving ord,yojson,eq,show]

    val decode : Cstruct.t -> (t, string) Result.result
  end
end

module ECDSA :
sig
  module Public :
  sig
    type t =
      { modulus : Z.t
      ; coefficient_a : Z.t
      ; coefficient_b : Z.t
      ; base_point_g : Z.t
      ; base_point_r_order : Z.t
      ; public_point_y : Z.t
      ; cofactor_f : Z.t
      }
    [@@deriving ord,yojson,eq,show]

    val decode : Cstruct.t -> (t, string) Result.result
  end
end