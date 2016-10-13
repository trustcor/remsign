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
    Application.ensure_all_started(:con_cache)
    on_exit fn ->
      Application.stop(:con_cache)
    end
    {:ok, cc} = ConCache.start(name: :test_nonce_cc)
    {:ok, pid} = Remsign.Registrar.start_link( cfg, &test_key_lookup/2,
      fn n -> Remsign.Utils.cc_store_nonce(cc, n) end )
    [ cfg: cfg, nag: a, pid: pid, cc: cc ]
  end

  test "register backend", ctx do
    {:ok, _be} = Remsign.Backend.start_link(
      %{
        ident: "test-backend",
        signkey: test_key_lookup("test-backend", :private),
        signalg: "Ed25519",
        keys: %{
          "key1" => %{ "private" => test_key_lookup("key1", :private),
                       "public" => test_key_lookup("key1", :public)
                     },
          "key2" => %{ "private" => test_key_lookup("key2", :private),
                       "public" => test_key_lookup("key2", :public)
                     }
        },
        verification_keys: %{
          "test-dealer" => %{ "crv" => "Ed25519",
                              "kty" => "OKP",
                              "x" => "PgH0Bdgk0y6eVC7GrmJO2bnFick1nzSCcTPHAR4xcO0"
                            }
        },
        host: get_in(ctx, [:cfg, :registrar, :addr]),
        port: get_in(ctx, [:cfg, :registrar, :port])
      }
    )
    reg = Remsign.Backend.register()
    assert is_map(reg)
    assert Map.get(reg, "command") == "register"
    hm = Map.get(reg, "hmac_key")
    port = Map.get(reg, "port")
    assert String.match?(hm, ~r/^[0-9a-f]+$/) and byte_size(hm) == 64
    assert port == 21000
  end

  test "registrar backend comms", ctx do
    {:ok, _be} = Remsign.Backend.start_link(
      %{
        ident: "test-backend",
        signkey: test_key_lookup("test-backend", :private),
        signalg: "Ed25519",
        keys: %{
          "key2" => %{ "private" => test_key_lookup("key2", :private),
                       "public" => test_key_lookup("key2", :public)
                     }
        },
        verification_keys: %{
          "test-dealer" => %{ "crv" => "Ed25519",
                              "kty" => "OKP",
                              "x" => "PgH0Bdgk0y6eVC7GrmJO2bnFick1nzSCcTPHAR4xcO0"
                            }
        },
        host: get_in(ctx, [:cfg, :registrar, :addr]),
        port: get_in(ctx, [:cfg, :registrar, :port])
      }
    )
    reg = Remsign.Backend.register()
    assert Remsign.Registrar.ping() == "pong"
  end

  def kconfig(ctx, kn) do
    %{
      ident: "test-backend",
      signkey: test_key_lookup("test-backend", :private),
      signalg: "Ed25519",
      keys: %{
        kn => %{ "private" => test_key_lookup(kn, :private),
                 "public" => test_key_lookup(kn, :public)
               }
      },
      verification_keys: %{
        "test-dealer" => %{ "crv" => "Ed25519",
                            "kty" => "OKP",
                            "x" => "PgH0Bdgk0y6eVC7GrmJO2bnFick1nzSCcTPHAR4xcO0"
                          }
      },
      host: get_in(ctx, [:cfg, :registrar, :addr]),
      port: get_in(ctx, [:cfg, :registrar, :port])
    }
  end

  def assert_valid_sig(ctx, kn) do
    reg = Remsign.Backend.register()
    hm = Remsign.Backend.hmac()
    d = << 0 :: 160 >>
    rep = Remsign.Registrar.sign(kn, :sha, d)
    case Poison.decode(rep) do
      {:error, _} ->
        {:ok, sig} =
          Remsign.Utils.unwrap(rep,
            fn _kn, :public -> JOSE.JWK.from_oct(hm) end,
            ctx[:skew],
            fn n -> Remsign.Utils.cc_store_nonce(ctx[:cc], n) end) |>
          Base.decode16(case: :mixed)

        {%{ kty: kty }, kk} = test_key_lookup(kn, :public) |> JOSE.JWK.from_map |> JOSE.JWK.to_key
        v = case kty do
              :jose_jwk_kty_rsa -> :public_key.verify({:digest, d}, :sha, sig, kk)
              :jose_jwk_kty_dsa -> :public_key.verify({:digest, d}, :sha, sig, kk)
              :jose_jwk_kty_ec -> :public_key.verify({:digest, d}, :sha, sig, kk)
              :jose_jwk_kty_okp_ed25519 -> :jose_curve25519.ed25519_verify(sig, d, kk)
            end
        assert v == true
      {:ok, { :error, err }} -> assert err == :expect_fail
    end
  end

  test "registrar backend signing with unknown hash", ctx do
    {:ok, _be} = Remsign.Backend.start_link(kconfig(ctx, "key1"))
    reg = Remsign.Backend.register()

    assert Remsign.Registrar.sign("key1", :bad_hash, << 0 :: 160 >>) == {:error, :unknown_digest_type}
  end

  test "registrar backend with unknown key", ctx do
    {:ok, _be} = Remsign.Backend.start_link(kconfig(ctx, "key1"))
    reg = Remsign.Backend.register()

    assert Remsign.Registrar.sign("bad-key", :sha, << 0 :: 160 >>) == {:error, :unknown_key}
  end

  test "registrar backend signing (ECDSA)", ctx do
    {:ok, _be} = Remsign.Backend.start_link(kconfig(ctx, "key2"))
    assert_valid_sig(ctx, "key2")
  end

  test "registrar backend signing (RSA)", ctx do
    {:ok, _be} = Remsign.Backend.start_link(kconfig(ctx, "key1"))
    assert_valid_sig(ctx, "key1")
  end

  test "registrar backend signing (Ed25519)", ctx do
    {:ok, _be} = Remsign.Backend.start_link(kconfig(ctx, "key3"))
    assert_valid_sig(ctx, "key3")
  end

end
