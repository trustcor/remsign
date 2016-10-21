defmodule RemsignBackendTest do
  use ExUnit.Case

  def test_nonce_store(a, n) do
    case Agent.get(a, fn ms -> MapSet.member?(ms, n) end) do
      true ->
        false # already in store
      false ->
        Agent.update(a, fn ms -> MapSet.put(ms, n) end)
        true
    end
  end

  import TestUtils

  setup do
    cfg = %{
      registrar: %{
        addr: "127.0.0.1",
        port: 25000,
        base_port: 21000,
        clock_skew: 30,
        keyid: "test-dealer",
        alg: "Ed25519"
      }
    }
    {:ok, a} = Agent.start_link(fn -> MapSet.new() end)

    Enum.each([:con_cache, :chumak], fn a -> Application.ensure_all_started(a) end)
    on_exit fn ->
      Enum.each([:con_cache, :chumak], fn a -> Application.stop(a) end)
    end
    {:ok, kl} = TestKeyLookup.start_link()
    {:ok, cc} = ConCache.start(name: :test_nonce_cc)
    {:ok, pid} = Remsign.Registrar.start_link( cfg, &test_key_lookup/2,
      fn n -> Remsign.Utils.cc_store_nonce(cc, n) end )
    [ cfg: cfg, nag: a, pid: pid, cc: cc, kl: kl ]
  end

  test "registrar backend comms", ctx do
    {:ok, _be} = Remsign.Backend.start_link(
      %{
        ident: "test-backend",
        signkey: "test-backend",
        signalg: "Ed25519",
        host: get_in(ctx, [:cfg, :registrar, :addr]),
        port: get_in(ctx, [:cfg, :registrar, :port]),
        num_workers: 1,
        nstore: fn n -> Remsign.Utils.cc_store_nonce(ctx[:cc], n) end
      },
      TestKeyLookup
    )
    assert Remsign.Registrar.ping() == "pong"
  end

  def kconfig(ctx) do
    %{
      ident: "test-backend",
      signkey: "test-backend",
      signalg: "Ed25519",
      host: get_in(ctx, [:cfg, :registrar, :addr]),
      port: get_in(ctx, [:cfg, :registrar, :port]),
      num_workers: 1,
      nstore: fn n -> Remsign.Utils.cc_store_nonce(ctx[:cc], n) end
    }
  end

  def assert_valid_sig(ctx, kn) do
    hm = Remsign.Backend.hmac(kn)
    d = zd
    {_hmk, rep} = Remsign.Registrar.sign(kn, :sha, d)
    case Poison.decode(rep) do
      {:ok, %{ "error" => err }} -> assert err == :expect_fail
      {:error, _} ->
        {:ok, sig} = Remsign.Utils.unwrap(rep, fn _kn, :public -> JOSE.JWK.from_oct(hm) end,
          ctx[:skew], fn n -> Remsign.Utils.cc_store_nonce(ctx[:cc], n) end) |>
          Base.decode16(case: :mixed)
          {%{ kty: kty }, kk} = test_key_lookup(kn, :public) |> JOSE.JWK.from_map |> JOSE.JWK.to_key
          d = Base.decode16!(d)
          v = case kty do
                :jose_jwk_kty_rsa -> :public_key.verify({:digest, d}, :sha, sig, kk)
                :jose_jwk_kty_dsa -> :public_key.verify({:digest, d}, :sha, sig, kk)
                :jose_jwk_kty_ec -> :public_key.verify({:digest, d}, :sha, sig, kk)
                :jose_jwk_kty_okp_ed25519 -> :jose_curve25519.ed25519_verify(sig, d, kk)
              end
          assert v == true
    end
  end

  def zd, do: << 0 :: 160 >> |> Base.encode16(case: :lower)

  test "registrar backend signing with unknown hash", ctx do
    {:ok, _be} = Remsign.Backend.start_link(kconfig(ctx), TestKeyLookup)
    assert Remsign.Registrar.sign("key1", :bad_hash, zd) == {:error, :unknown_digest_type}
  end

  test "registrar backend with unknown key", ctx do
    {:ok, _be} = Remsign.Backend.start_link(kconfig(ctx), TestKeyLookup)
    assert Remsign.Registrar.sign("bad-key", :sha, zd) == {nil, {:error, :unknown_key}}
  end

  test "registrar backend signing (ECDSA)", ctx do
    {:ok, _be} = Remsign.Backend.start_link(kconfig(ctx), TestKeyLookup)
    assert_valid_sig(ctx, "key2")
  end

  test "registrar backend signing (RSA)", ctx do
    {:ok, _be} = Remsign.Backend.start_link(kconfig(ctx), TestKeyLookup)
    assert_valid_sig(ctx, "key1")
  end

  test "registrar backend signing (Ed25519)", ctx do
    {:ok, _be} = Remsign.Backend.start_link(kconfig(ctx), TestKeyLookup)
    assert_valid_sig(ctx, "key3")
  end

end
