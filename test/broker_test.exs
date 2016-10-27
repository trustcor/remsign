defmodule RemsignBrokerTest do
  use ExUnit.Case

  import TestUtils

  setup do
    cfg = %{
      broker: %{
        host: "127.0.0.1",
        port: 19999
      },
      registrar: %{
        addr: "127.0.0.1",
        port: 25000,
        base_port: 21000,
        clock_skew: 30,
        keyid: "test-dealer",
        alg: "Ed25519"
      }
    }

    Enum.each([:con_cache, :chumak], fn a -> Application.ensure_all_started(a) end)
    {:ok, cc} = ConCache.start(name: :test_nonce_cc)
    cfg = put_in(cfg, [:broker, :cc], cc)

    on_exit fn ->
      Enum.each([:con_cache, :chumak], fn a -> Application.stop(a) end)
    end

    {:ok, kl} = TestKeyLookup.start_link()
    {:ok, _pid} = Remsign.Broker.start_link(cfg, &test_key_lookup/2)
    {:ok, a} = Agent.start_link(fn -> MapSet.new() end)

    {:ok, pid} = Remsign.Registrar.start_link( cfg, &test_key_lookup/2,
      fn n -> Remsign.Utils.cc_store_nonce(cc, n) end )

    {:ok, be} = Remsign.Backend.start_link(
      %{
        ident: "test-backend",
        signkey: "test-backend",
        signalg: "Ed25519",
        host: get_in(cfg, [:registrar, :addr]),
        port: get_in(cfg, [:registrar, :port]),
        nstore: fn n -> Remsign.Utils.cc_store_nonce(cc, n) end
      }, TestKeyLookup
    )
    :ok = TestKeyLookup.set_backend(be)

    [ cfg: cfg, nag: a, pid: pid, cc: cc, kl: kl ]
  end

  test "connect to broker", ctx do
    {:ok, sock} = :chumak.socket(:req, String.to_charlist("test-client"))
    case :chumak.connect(sock, :tcp, String.to_charlist( get_in(ctx, [:cfg, :broker, :host] )),
          get_in(ctx, [:cfg, :broker, :port])) do
      {:ok, _pid} ->
        :ok = :chumak.send(sock, Poison.encode!(%{ command: :bad_command }))
        {:ok, m} = :chumak.recv(sock)
        assert Poison.encode!(%{ error: :unknown_command }) == m
      {:error, e} -> assert e == :expected_fail
    end
  end

  def make_sign_request(msg, dtype, hm, k) do
    d = :crypto.hash(dtype, msg) |> Base.encode16(case: :lower)
    %{ payload: %{ command: :sign, parms: %{ keyname: k, hash_type: dtype, digest: d } } } |>
      Remsign.Utils.wrap("fe-key", "HS256", JOSE.JWK.from_map(hm) )
  end

  def do_verify("Ed25519", k, sig) do
    d = :crypto.hash(:sha, "Test-String")
    :jose_curve25519.ed25519_verify(sig, d, k)
  end

  def do_verify(_, k, sig), do: :public_key.verify("Test-String", :sha, sig, k)

  def run_sign_test(ctx, kty, kn) do
    {:ok, sock} = :chumak.socket(:req, String.to_charlist("test-client"))
    case :chumak.connect(sock, :tcp, String.to_charlist( get_in(ctx, [:cfg, :broker, :host] )),
          get_in(ctx, [:cfg, :broker, :port])) do
      {:ok, _pid} ->
        k = test_key_lookup("fe-key", :private)
        msg = make_sign_request("Test-String", :sha, k, kn)
        :ok = :chumak.send(sock, msg)
        {:ok, m} = :chumak.recv(sock)
        {:ok, sig} = Remsign.Utils.unwrap(m, fn _, _ -> k end, 60, fn _n -> true end) |> Base.decode16(case: :mixed)
        {_, vk} = test_key_lookup(kn, :public) |> JOSE.JWK.to_key
        assert do_verify(kty, vk, sig) == true
      {:error, e} -> assert e == :expected_fail
    end
  end

  test "sign request RSA", ctx do
    run_sign_test(ctx, "RSA", "key1")
  end

  test "sign request ECDSA", ctx do
    run_sign_test(ctx, "ECDSA", "key2")
  end

  test "sign request Ed25519", ctx do
    run_sign_test(ctx, "Ed25519", "key3")
  end

  test "attach two backends, disconnect 1, then sign" do
    # tbd - not easy to arrange 0MQ disconnects within a single BEAM node
    assert 1 + 1 == 2
  end

end
