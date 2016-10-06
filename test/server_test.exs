defmodule RemsignServerTest do
  use ExUnit.Case

  setup do
    cfg = %{
      registrar: %{
        addr: "127.0.0.1",
        port: 25000,
        clock_skew: 30
      }
    }
    [cfg: cfg]
  end

  def test_key_lookup(kid) do
    case kid do
      "secret-key" ->
        %{ "public" => %{ "kty" => "oct",
                          "k" => Base.url_encode64("secret", padding: false)
                        }}
      "secret-ed" ->
        %{ "public" => %{ "crv" => "Ed25519",
                          "kty" => "OKP",
                          "x" => "oGnaw4dQKKYuKNFs8rYfhmVkw6_FKjXk4o7kmBHq2sE" }}
      "secret-ecdsa" ->
        %{ "public" => %{ "kty" => "EC",
                          "crv" => "P-256",
                          "x" => "80fv3sOdpkeQJ61ysp6FUe5NcNa9jWPlJ_eC6kd0mpA",
                          "y" => "XhRKUz4GU4xdRXucOGr4S1oCC3RQXp7II6ARklBBFgs"
                        }}
      _ -> nil
    end
  end

  def test_nonce_store(a, n) do
    case Agent.get(a, fn ms -> MapSet.member?(ms, n) end) do
      true ->
        false # already in store
      false ->
        Agent.update(a, fn ms -> MapSet.put(ms, n) end)
        true
    end
  end

  def connect(ctx) do
    {:ok, a} = Agent.start_link(fn -> MapSet.new() end)
    {:ok, _pid} = Remsign.Registrar.start_link( ctx[:cfg], &test_key_lookup/1,
      fn n -> test_nonce_store(a, n) end )

    sock = case :chumak.socket(:req, 'test-reg-ident') do
             {:error, {:already_started, sockpid}} -> sockpid
             {:ok, sockpid} -> sockpid
             e ->
               IO.puts("#{inspect(e)} received")
               nil
           end
    {:ok, _pid} = :chumak.connect(sock, :tcp, '127.0.0.1', 25000)
    :timer.sleep(5)
    sock
  end

  test "bind registrar", ctx do
    sock = connect(ctx)
    assert :chumak.send(sock, "ping") == :ok
    case :chumak.recv(sock) do
      {:ok, msg} ->
        assert msg == "pong"
      e ->
        assert e == :fail
    end
  end

  test "send bad json message", ctx do
    sock = connect(ctx)
    msg = "}{#[]"
    assert :chumak.send(sock, msg) == :ok
    case :chumak.recv(sock) do
      e ->
        assert e == {:ok, Poison.encode!(%{ error: :invalid_jwt })}
    end
  end

  test "send json (but not JWT) message", ctx do
    sock = connect(ctx)
    msg = Poison.encode!(%{ command: :health })
    assert :chumak.send(sock, msg) == :ok
    case :chumak.recv(sock) do
      e ->
        assert e == {:ok, Poison.encode!(%{ error: :invalid_jwt })}
    end
  end

  test "send JWT message", ctx do
    sock = connect(ctx)
    k = Joken.Signer.hs("HS256", "secret")
    msg = %{ payload: %{ command: :health} } |>
      Joken.token |>
      Joken.with_sub("secret-key") |>
      Joken.with_iat(DateTime.utc_now) |>
      Joken.with_jti(Remsign.Utils.make_nonce) |>
      Joken.with_signer(k) |>
      Joken.sign |>
      Joken.get_compact
    assert :chumak.send(sock, msg) == :ok
    case :chumak.recv(sock) do
      e ->
        assert e == {:ok, Poison.encode!(%{ error: :unknown_command })}
    end
  end

  defp screw_sig(msg) do
    # flip the top bit on each byte of the signature component

    use Bitwise

    [h, p, s] = String.split(msg, ".", parts: 3)
    {:ok, sv} = Base.url_decode64(s, padding: false)
    Enum.join([h,p,:binary.bin_to_list(sv) |>
                Enum.map(fn x -> bxor(x, 128) end ) |>
                :binary.list_to_bin() |>
                Base.url_encode64(padding: false)], ".")

  end

  test "send JWT message with ED25519", ctx do
    sock = connect(ctx)
    k = Joken.Signer.eddsa("Ed25519",
      %{
        "crv" => "Ed25519",
        "d" => "XONvUY25F9MUdwVreW701iA-FyBiUzIYKmDc1AWSGT0",
        "kty" => "OKP",
        "x" => "oGnaw4dQKKYuKNFs8rYfhmVkw6_FKjXk4o7kmBHq2sE"
      })
    msg = %{ payload: %{ command: :health} } |>
      Joken.token |>
      Joken.with_sub("secret-ed") |>
      Joken.with_iat(DateTime.utc_now) |>
      Joken.with_jti(Remsign.Utils.make_nonce) |>
      Joken.with_signer(k) |>
      Joken.sign |>
      Joken.get_compact
    assert :chumak.send(sock, msg) == :ok
    case :chumak.recv(sock) do
      e ->
        assert e == {:ok, Poison.encode!(%{ error: :unknown_command })}
    end
  end

  test "send JWT message with ECDSA", ctx do
    sock = connect(ctx)
    k = Joken.Signer.es("ES256",
      %{
        "kty" => "EC",
        "crv" => "P-256",
        "d" => "0cXg0MW6FoWWPMf7gGOMQyLHkFGwRq0I34a24hiZ1DM",
        "x" => "80fv3sOdpkeQJ61ysp6FUe5NcNa9jWPlJ_eC6kd0mpA",
        "y" => "XhRKUz4GU4xdRXucOGr4S1oCC3RQXp7II6ARklBBFgs"
      })
    msg = %{ payload: %{ command: :health} } |>
      Joken.token |>
      Joken.with_sub("secret-ecdsa") |>
      Joken.with_iat(DateTime.utc_now) |>
      Joken.with_jti(Remsign.Utils.make_nonce) |>
      Joken.with_signer(k) |>
      Joken.sign |>
      Joken.get_compact
    assert :chumak.send(sock, msg) == :ok
    case :chumak.recv(sock) do
      e ->
        assert e == {:ok, Poison.encode!(%{ error: :unknown_command })}
    end
  end

  test "send JWT message with ED25519 (corrupt sig)", ctx do
    sock = connect(ctx)
    k = Joken.Signer.eddsa("Ed25519",
      %{
        "crv" => "Ed25519",
        "d" => "XONvUY25F9MUdwVreW701iA-FyBiUzIYKmDc1AWSGT0",
        "kty" => "OKP",
        "x" => "oGnaw4dQKKYuKNFs8rYfhmVkw6_FKjXk4o7kmBHq2sE"
      })
    msg = %{ payload: %{ command: :health} } |>
      Joken.token |>
      Joken.with_sub("secret-ed") |>
      Joken.with_iat(DateTime.utc_now) |>
      Joken.with_jti(Remsign.Utils.make_nonce) |>
      Joken.with_signer(k) |>
      Joken.sign |>
      Joken.get_compact |>
      screw_sig
    assert :chumak.send(sock, msg) == :ok
    case :chumak.recv(sock) do
      e ->
        assert e == {:ok, Poison.encode!(%{ error: :invalid_signature })}
    end
  end

  test "send duplicate JWT message", ctx do
    sock = connect(ctx)
    k = Joken.Signer.hs("HS256", "secret")
    msg = %{ payload: %{ command: :health} } |>
      Joken.token |>
      Joken.with_sub("secret-key") |>
      Joken.with_iat(DateTime.utc_now) |>
      Joken.with_jti(Remsign.Utils.make_nonce) |>
      Joken.with_signer(k) |>
      Joken.sign |>
      Joken.get_compact
    :chumak.send(sock, msg)
    :chumak.recv(sock)

    # send again (with same nonce)

    :chumak.send(sock, msg)
    assert :chumak.recv(sock) == {:ok, Poison.encode!(%{ error: :invalid_payload })}
  end

  test "send JWT message with old timestamp", ctx do
    sock = connect(ctx)
    {:ok, old_ts} = ((DateTime.utc_now |> DateTime.to_unix) - 60) |> DateTime.from_unix
    k = Joken.Signer.hs("HS256", "secret")
    msg = %{ payload: %{ command: :health} } |>
      Joken.token |>
      Joken.with_sub("secret-key") |>
      Joken.with_iat(old_ts) |>
      Joken.with_jti(Remsign.Utils.make_nonce) |>
      Joken.with_signer(k) |>
      Joken.sign |>
      Joken.get_compact
    assert :chumak.send(sock, msg) == :ok
    case :chumak.recv(sock) do
      e ->
        assert e == {:ok, Poison.encode!(%{ error: :invalid_payload })}
    end
  end

  test "send JWT message with bad secret", ctx do
    sock = connect(ctx)
    k = Joken.Signer.hs("HS256", "bad-secret")
    msg = %{ payload: %{ command: :health} } |>
      Joken.token |>
      Joken.with_sub("secret-key") |>
      Joken.with_iat(DateTime.utc_now) |>
      Joken.with_jti(Remsign.Utils.make_nonce) |>
      Joken.with_signer(k) |>
      Joken.sign |>
      Joken.get_compact
    assert :chumak.send(sock, msg) == :ok
    case :chumak.recv(sock) do
      e ->
        assert e == {:ok, Poison.encode!(%{ error: :invalid_signature })}
    end
  end
end