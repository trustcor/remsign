defmodule Remsign.Backend do
  @moduledoc """
  Functionality for a backend server, which gets registered to one or more
  brokers which then send signing requests to it.
  """
  use GenServer
  import Logger, only: [log: 2]

  def init([cfg = %{}]) do
    sock = case :chumak.socket(:req, String.to_charlist(Map.get(cfg, :ident))) do
             {:error, {:already_started, sockpid}} -> sockpid
             {:ok, sockpid} -> sockpid
             e ->
               log(:error, "#{inspect(e)} on chumak connect() received")
               nil
           end
    {pub, priv} = Remsign.Utils.generate_rsa(Map.get(cfg, :modulus_size, 2048))
    {:ok, _pid} = :chumak.connect(sock, :tcp, String.to_charlist(cfg[:host]), cfg[:port])
    :chumak.send(sock, "ping")
    case :chumak.recv(sock) do
      {:ok, "pong"} ->
        {:ok, Map.put(cfg, :sock, sock) |> Map.put(:ekpriv, priv) |> Map.put(:ekpub, pub)}
      e ->
        log(:error, "Non pong error from registrar: #{inspect(e)}")
        {:error, :no_registry_connect}
    end
  end

  def start_link(cfg = %{}) do
    defaults = %{
      num_workers: 1,
      sock: nil,
      host: "127.0.0.1",
      port: 25000,
      ident: "backend",
      skew: 60,
      keys: %{},
      verification_keys: %{}
    }
    GenServer.start_link __MODULE__, [ Map.merge(defaults, cfg) ], name: __MODULE__
  end

  defp store_nonce(_n) do
    true
  end

  defp get_public_keys(ks) do
    Enum.map(ks, fn {kn, k} -> {kn, Map.get(k, "public")} end) |> Enum.into(%{})
  end

  def register() do
    GenServer.call __MODULE__, :register
  end

  defp handle_register_response(%{ "command" => "register", "response" => resp = %{ "ciphertext" => _ } }, st) do
    alg = %{alg: :jose_jwe_alg_rsa, enc: :jose_jwe_enc_chacha20_poly1305}
    {pt, _m} = JOSE.JWE.block_decrypt(JOSE.JWK.from_map(st[:ekpriv]), {alg, resp})
    case Poison.decode(pt) do
      {:ok, m = %{}} -> Map.put(m, "command", "register")
      _ -> {:error, :malformed_response}
    end
  end

  defp handle_register_response(_, _st) do
    { :error, :malformed_response }
  end

  def handle_call(:register, _from, st) do
    pk = get_public_keys(st[:keys])
    msg = %{ command: "register",
             params: %{
               pubkeys: pk,
               ekey: st[:ekpub]
             }
           }
    m = Remsign.Utils.wrap(msg, st[:ident], st[:signalg], st[:signkey] )
    :chumak.send(st[:sock],m)
    r = case :chumak.recv(st[:sock]) do
          {:ok, rep} ->
            Remsign.Utils.unwrap(rep, fn k, :public -> get_in(st, [:verification_keys, k]) end, st[:skew], &store_nonce/1) |>
              handle_register_response(st)

          e ->
            log(:error, "Unexpected reply from register: #{inspect(e)}")
        end
    {:reply, r, st}
  end

end
