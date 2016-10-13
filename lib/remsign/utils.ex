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
        r = (abs(d) < skew)
        log(:debug, "Result of time validation = #{inspect(r)}")
        r
      {:error, e} ->
        log(:error, "Timestamp format for #{inspect(t)} invalid: #{inspect(e)}")
        false
    end
  end

  def keyname(m), do: Joken.token(m) |> Joken.peek |> Map.get("sub")

  defp unwrap_h(m, kl, skew, nstore) do
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

  def unwrap(m, kl, skew, nstore) do
    case Poison.decode(m) do
      {:error, _} -> unwrap_h(m, kl, skew, nstore)
      {:ok, d} -> d
    end
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
        log(:debug, "Storing nonce #{inspect(n)} in #{inspect(cc)}")
        r = case ConCache.insert_new(cc, n, %ConCache.Item{value: true, ttl: ttl}) do
              :ok -> true
              {:error, :already_exists} -> false
            end
        log(:debug, "Store nonce = #{inspect(r)}")
        r
      false ->
        log(:warn, "Invalid nonce format")
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

  defp known_hash_h("sha"), do: :sha
  defp known_hash_h("sha1"), do: :sha
  defp known_hash_h("sha224"), do: :sha224
  defp known_hash_h("sha256"), do: :sha256
  defp known_hash_h("sha384"), do: :sha384
  defp known_hash_h("sha512"), do: :sha512
  defp known_hash_h("md5"), do: :md5
  defp known_hash_h("md4"), do: :md4
  defp known_hash_h("md2"), do: :md2
  defp known_hash_h(_), do: nil

  @doc """
  Return an atom corresponding to a hash type, or nil if the hash is unknown
  """
  def known_hash(h) when is_binary(h) do
    String.replace(h, ~r/[^A-Za-z0-9]/, "") |> String.downcase |> known_hash_h
  end
end
