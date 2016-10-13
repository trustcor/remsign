defmodule RemsignBackendTest do
  use ExUnit.Case

  import TestUtils

  setup do
    cfg = %{
      broker: %{
        host: "127.0.0.1",
        port: 19999,
        keys: %{ "fe-key" => test_key_lookup("fe-key", :private) }
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
    {:ok, cc} = ConCache.start(name: :test_nonce_cc)
    cfg = put_in(cfg, [:broker, :cc], cc)

    {:ok, _pid} = Remsign.Broker.start_link(cfg)
    {:ok, a} = Agent.start_link(fn -> MapSet.new() end)

    Application.ensure_all_started(:con_cache)
    on_exit fn ->
      Application.stop(:con_cache)
    end

    {:ok, pid} = Remsign.Registrar.start_link( cfg, &test_key_lookup/2,
      fn n -> Remsign.Utils.cc_store_nonce(cc, n) end )

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
        host: get_in(cfg, [:registrar, :addr]),
        port: get_in(cfg, [:registrar, :port])
      }
    )
    Remsign.Backend.register()

    [ cfg: cfg, nag: a, pid: pid, cc: cc ]
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

  test "sign request", ctx do
    {:ok, sock} = :chumak.socket(:req, String.to_charlist("test-client"))
    case :chumak.connect(sock, :tcp, String.to_charlist( get_in(ctx, [:cfg, :broker, :host] )),
          get_in(ctx, [:cfg, :broker, :port])) do
      {:ok, _pid} ->
        k = test_key_lookup("fe-key", :private)
        msg = make_sign_request("Test-String", :sha, k, "key1")
        :ok = :chumak.send(sock, msg)
        {:ok, m} = :chumak.recv(sock)
        {:ok, sig} = Remsign.Utils.unwrap(m, fn _, _ -> k end, 60, fn _n -> true end) |> Base.decode16(case: :mixed)
        {_, vk} = test_key_lookup("key1", :public) |> JOSE.JWK.to_key
        assert :public_key.verify("Test-String", :sha, sig, vk) == true
      {:error, e} -> assert e == :expected_fail
    end
  end


end
