defmodule Remsign.Pubkey do
  import Logger, only: [log: 2]

  @moduledoc """
  Utilities to handle public key information
  """

  defp int_to_64(i) when is_integer(i), do: :binary.encode_unsigned(i) |> Base.encode64

  def keyid(%{ "kty" => "RSA", "n" => modulus, "e" => exponent }) when is_binary(modulus) and is_binary(exponent) do
    :crypto.hash(:sha, "rsa" <> exponent <> modulus) |>
      Base.encode16(case: :lower)
  end

  def keyid(%{ "kty" => "oct", "k" => key }) when is_binary(key) do
    :crypto.hash(:sha, "oct" <> key) |> Base.encode16(case: :lower)
  end

  def keyid(%{ "kty" => "OKP", "crv" => "Ed25519", "x" => pubkey }) when is_binary(pubkey) do
    :crypto.hash(:sha, "ed25519" <> pubkey) |>
      Base.encode16(case: :lower)
  end

  def keyid(%{ "kty" => "EC", "crv" => "P-256", "x" => x, "y" => y }) when is_binary(x) and is_binary(y) do
    :crypto.hash(:sha, "ecp-256" <> x <> y) |> Base.encode16(case: :lower)
  end

  def keyid(_, _), do: nil

  defp joken_key({{:RSAPublicKey, n, e}, nil}) when is_integer(n) and is_integer(e) do
    %{
      "kty" => "RSA",
      "n" => int_to_64(n),
      "e" => int_to_64(e)
    }
  end

  defp joken_key({k, parms}) do
    log(:error, "Invalid/Unknown key: #{inspect(k, pretty: true)}/#{inspect(parms, pretty: true)}")
    nil
  end

  def keytype(%{ "kty" => "EC", "crv" => "P-256" }), do: :ecdsa
  def keytype(%{ "kty" => "OKP", "crv" => "Ed25519" }), do: :ed25519
  def keytype(%{ "kty" => kt }) when is_binary(kt), do: (String.downcase(kt) |> String.to_atom)

  def get_public_key_from_bits({1, 2, 840, 113549, 1, 1, 1}, spbits, _parms) do
    {:public_key.der_decode(:RSAPublicKey, spbits), nil}
  end

  def get_public_key_from_bits({1, 2, 840, 10045, 2, 1}, _spbits, _parms) do
    :not_implemented_yet
  end

  defp load_ed25519_pubkey(pkdata) do
    case Base.decode64(pkdata) do
      {:ok, d} ->
        case d do
          << 11::32, "ssh-ed25519", 32::32, pubkey::256 >> ->
            %{ "kty" => "OKP",
               "crv" => "Ed25519",
               "x" => Base.url_encode64(:binary.encode_unsigned(pubkey), padding: false) }
          s ->
            log(:warn, "Ill-formed Ed25519 key #{inspect(pkdata)} -> #{inspect(s)}")
            nil
        end
      _e ->
        log(:error, "#{inspect(pkdata)} is not valid base64")
        nil
    end
  end

  defp load_ecdsa_pubkey(pkdata) do
    case Base.decode64(pkdata) do
      {:ok, d} ->
        case d do
          << 19::32, "ecdsa-sha2-nistp256", 8::32, "nistp256", _len :: 32, _pad :: 8, x :: 256, y :: 256 >> ->
            %{ "kty" => "EC",
               "crv" => "P-256",
               "x" => Base.url_encode64(:binary.encode_unsigned(x), padding: false),
               "y" => Base.url_encode64(:binary.encode_unsigned(y), padding: false) }
          s ->
            log(:warn, "Ill-formed EcDSA key #{inspect(pkdata)} -> #{inspect(s)}")
            nil
        end
      _e ->
        log(:error, "#{inspect(pkdata)} is not valid base64")
        nil
    end
  end

  def load_key(keydata) do
    case :public_key.pem_decode(keydata) do
      [{:SubjectPublicKeyInfo, spki, _aux}] ->
        {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, algid, parms}, spbits} =
          :public_key.der_decode(:SubjectPublicKeyInfo, spki)
        get_public_key_from_bits(algid, spbits, parms) |> joken_key
      [{:RSAPublicKey, bits, _}] ->
        pk = {:RSAPublicKey, _n, _e} = :public_key.der_decode(:RSAPublicKey, bits)
        joken_key({pk, nil})
      [] ->
        # try openssh pubkey format
        [kt, pkdata | _rest] = String.split(keydata, " ") |> Enum.map(&String.trim/1)
        case kt do
          "ssh-ed25519" ->
            load_ed25519_pubkey(pkdata)
          "ecdsa-sha2-nistp256" ->
            load_ecdsa_pubkey(pkdata)
          e ->
            log(:error, "Unknown public key type: #{inspect(e)}")
            nil
        end
    end
  end

end
