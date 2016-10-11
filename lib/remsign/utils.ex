defmodule Remsign.Utils do
  import Logger, only: [log: 2]

  def get_in_default(m, kl, d) do
    case get_in(m, kl) do
      nil -> d
      r -> r
    end
  end

  def make_nonce, do: :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)

  def validate_clock(t, skew) do
    case Timex.parse(t, "{ISO:Extended:Z}") do
      {:ok, ts} ->
        d = Timex.diff(DateTime.utc_now, ts, :seconds)
        abs(d) < skew
      {:error, e} ->
        log(:error, "Timestamp format for #{inspect(t)} invalid: #{inspect(e)}")
        false
    end
  end

  def unwrap(m, kl, skew, nstore) do
    jp = Joken.token(m) |> Joken.peek
    alg = case JOSE.JWS.peek_protected(m) |> Poison.decode do
            {:ok, %{ "alg" => algo }} -> algo
            _ -> "HS256" # default
          end

    keyid = jp["sub"]
    sig = %Joken.Signer{ jws: %{ "alg" => alg },
                         jwk: kl.(keyid, :public)}
    log(:debug, "Verification: keyid = #{inspect(keyid)}, alg = #{alg}, sig = #{inspect(sig)}")
    v = m |>
      Joken.token |>
      Joken.with_signer(sig) |>
      Joken.with_validation("iat", fn t -> validate_clock(t, skew) end) |>
      Joken.with_validation("jti", nstore) |>
      Joken.verify
    log(:debug, "Verify result = #{inspect(v)}")
    v.claims["payload"]
  end

  def wrap(m, keyid, alg, sig, opts \\ []) do
    ts = Keyword.get(opts, :ts, DateTime.utc_now)
    nonce = Keyword.get(opts, :nonce, Remsign.Utils.make_nonce)
    m |>
      Joken.token |>
      Joken.with_sub(keyid) |>
      Joken.with_iat(ts) |>
      Joken.with_jti(nonce) |>
      Joken.with_signer(%Joken.Signer{jws: %{ "alg" => alg }, jwk: sig} ) |>
      Joken.sign |>
      Joken.get_compact
  end

  defp valid_nonce_h?(_, l) when is_integer(l) and (l < 8 or l > 32), do: false
  defp valid_nonce_h?(n, _) when is_binary(n) do
    String.downcase(n) |> String.match?(~r/^[0-9a-f]+$/)
  end

  defp valid_nonce?(n) when is_binary(n), do: valid_nonce_h?(n, byte_size(n))
  defp valid_nonce?(_), do: false

  @doc """
  Attempt to insert a valid nonce into a ConCache store.
  If the nonce is not valid, return false
  If the item is already present return false.
  Otherwise return true.
  """
  def cc_store_nonce(cc, n, ttl \\ 60) when is_binary(n) do
    case valid_nonce?(n) do
      true ->
        case ConCache.insert_new(cc, n, true) do
          :ok -> true
          {:error, :already_exists} -> false
        end
      false ->
        false # invalid nonce format
    end
  end

  @doc """
  Generate an RSA public/private keypair with a modulus
  size of `mod`. Shells out to OpenSSL to actually perform
  key generation.
  """
  def generate_rsa(mod, opts \\ []) when is_integer(mod) do
    ossl = Keyword.get(opts, :openssl, "openssl")
    {priv, 0} = System.cmd(ossl, [ "genrsa", to_string(mod) ], [stderr_to_stdout: true])
    priv = :public_key.pem_decode(priv) |> List.first |> :public_key.pem_entry_decode(:RSAPrivateKey) |> JOSE.JWK.from_key |> JOSE.JWK.to_map
    pub = JOSE.JWK.to_public(priv) |> JOSE.JWK.to_map
    {elem(pub,1), elem(priv, 1)}
  end
end
