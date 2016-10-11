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

  def test_key_lookup("key1", :private) do
    {%{kty: :jose_jwk_kty_rsa},
     %{
       "kty" => "RSA",
       "d" => "iFPNeKfTwWq4oBdasyn6Ghkq-dXSjEAzs6tmg1VTJmk",
       "dp" => "Edo937xbhiI_piYx122_Zw",
       "dq" => "srWR6h0j5Rh6vjz2rIKe1w",
       "e" => "AQAB",
       "n" => "nQEYxYhNRjwqQ5HQTsPuSCNIz4eUGqjYrfEP1Fyq0Tk",
       "p" => "ynUGKA5R4pNqSg9TqbBMww",
       "q" => "xobGNiRu5_mB9CKLkY96Uw",
       "qi" => "WNjuNLi0IPts3V6IBfuXvg"
     }
    }
  end

  def test_key_lookup("key1", :public) do
    %{
      "e" => "AQAB",
      "kty" => "RSA",
      "n" => "nQEYxYhNRjwqQ5HQTsPuSCNIz4eUGqjYrfEP1Fyq0Tk="
    }
  end

  def test_key_lookup("test-dealer", :private) do
    %{
      "crv" => "Ed25519",
      "d" => "Ml05uJSjmIavqINFAJ1i3yJ65T0uyqjVwB7X1ehn4sg",
      "kty" => "OKP",
      "x" => "PgH0Bdgk0y6eVC7GrmJO2bnFick1nzSCcTPHAR4xcO0"
    }
  end

  def test_key_lookup("test-dealer", :public) do
    %{
      "crv" => "Ed25519",
      "kty" => "OKP",
      "x" => "PgH0Bdgk0y6eVC7GrmJO2bnFick1nzSCcTPHAR4xcO0"
    }
  end

  def test_key_lookup("test-backend", :private) do
    %{
      "crv" => "Ed25519",
      "d" => "XONvUY25F9MUdwVreW701iA-FyBiUzIYKmDc1AWSGT0",
      "kty" => "OKP",
      "x" => "oGnaw4dQKKYuKNFs8rYfhmVkw6_FKjXk4o7kmBHq2sE"
    }
  end

  def test_key_lookup("test-backend", :public) do
    %{
      "crv" => "Ed25519",
      "kty" => "OKP",
      "x" => "oGnaw4dQKKYuKNFs8rYfhmVkw6_FKjXk4o7kmBHq2sE"
    }
  end

  def test_key_lookup(_, _), do: nil

  setup do
    cfg = %{
      registrar: %{
        addr: "127.0.0.1",
        port: 25000,
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
    [ cfg: cfg, nag: a, pid: pid ]
  end

  test "register backend", ctx do
    {:ok, _be} = Remsign.Backend.start_link(
      %{
        ident: "test-backend",
        signkey: test_key_lookup("test-backend", :private),
        signalg: "Ed25519",
        keys: %{
          "key1" => %{
              "private" => test_key_lookup("key1", :private),
              "public" => test_key_lookup("key1", :public)
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
    assert Remsign.Backend.register() == %{ "command" => "register", "response" => "ok" }
  end

end
