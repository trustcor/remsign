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
      "secret-key" -> "secret"
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
    msg = %{ payload: %{ command: :health} } |>
      Joken.token |>
      Joken.with_sub("secret-key") |>
      Joken.with_iat(DateTime.utc_now) |>
      Joken.with_jti(Remsign.Utils.make_nonce) |>
      Joken.with_signer(Joken.hs256("secret")) |>
      Joken.sign |>
      Joken.get_compact
    assert :chumak.send(sock, msg) == :ok
    case :chumak.recv(sock) do
      e ->
        assert e == {:ok, Poison.encode!(%{ error: :unknown_command })}
    end
  end

  test "send duplicate JWT message", ctx do
    sock = connect(ctx)
    msg = %{ payload: %{ command: :health} } |>
      Joken.token |>
      Joken.with_sub("secret-key") |>
      Joken.with_iat(DateTime.utc_now) |>
      Joken.with_jti(Remsign.Utils.make_nonce) |>
      Joken.with_signer(Joken.hs256("secret")) |>
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
    msg = %{ payload: %{ command: :health} } |>
      Joken.token |>
      Joken.with_sub("secret-key") |>
      Joken.with_iat(old_ts) |>
      Joken.with_jti(Remsign.Utils.make_nonce) |>
      Joken.with_signer(Joken.hs256("secret")) |>
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
    msg = %{ payload: %{ command: :health} } |>
      Joken.token |>
      Joken.with_sub("secret-key") |>
      Joken.with_iat(DateTime.utc_now) |>
      Joken.with_jti(Remsign.Utils.make_nonce) |>
      Joken.with_signer(Joken.hs256("bad-secret")) |>
      Joken.sign |>
      Joken.get_compact
    assert :chumak.send(sock, msg) == :ok
    case :chumak.recv(sock) do
      e ->
        assert e == {:ok, Poison.encode!(%{ error: :invalid_signature })}
    end
  end
end
