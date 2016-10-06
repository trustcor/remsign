defmodule Remsign.Utils do
  import Logger, only: [log: 2]

  def get_in_default(m, kl, d) do
    case get_in(m, kl) do
      nil -> d
      r -> r
    end
  end

  def make_nonce, do: :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)

  def unwrap(m, kl) do
    jp = Joken.token(m) |> Joken.peek
    alg = case JOSE.JWS.peek_protected(m) |> Poison.decode do
            {:ok, %{ "alg" => algo }} -> algo
            _ -> "HS256" # default
          end

    keyid = jp["sub"]
    sig = %Joken.Signer{ jws: %{ "alg" => alg },
                         jwk: kl.(keyid, :public)}
    v = m |>
      Joken.token |>
      Joken.with_signer(sig) |>
      Joken.verify
    v.claims["payload"]
  end
end
