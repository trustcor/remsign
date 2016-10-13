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
      verification_keys: %{},
      hmac: nil
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

  def hmac() do
    GenServer.call __MODULE__, :hmac
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

  def handle_call({:store_nonce, n}, _from, st) do
    {:reply, store_nonce(n), st}
  end

  def handle_call(:hmac, _from, st) do
    {:reply, st[:hmac], st}
  end

  def handle_call(:register, _from, st) do
    import Supervisor.Spec, warn: false

    pk = get_public_keys(st[:keys])
    msg = %{ command: "register",
             params: %{
               pubkeys: pk,
               ekey: st[:ekpub]
             }
           }
    m = Remsign.Utils.wrap(msg, st[:ident], st[:signalg], st[:signkey] )
    :chumak.send(st[:sock],m)
    {r, hm} = case :chumak.recv(st[:sock]) do
                {:ok, rep} ->
                  rep = Remsign.Utils.unwrap(rep, fn k, :public -> get_in(st, [:verification_keys, k]) end, st[:skew], &store_nonce/1) |>
                    handle_register_response(st)
                  hm = Map.get(rep, "hmac_key")
                  {:ok, hm} = Base.decode16(hm, case: :mixed)
                  port = Map.get(rep, "port")

                  children = [
                    Honeydew.child_spec(:backend_pool, Remsign.BackendWorker, { st, port, hm }, workers: Map.get(st, :num_workers, 10))
                  ]
                  Supervisor.start_link(children, strategy: :one_for_one)
                  {rep, hm}
                e ->
                  log(:error, "Unexpected reply from register: #{inspect(e)}")
                  {nil, nil}
              end
    {:reply, r, Map.put(st, :hmac, hm)}
  end

end

defmodule Remsign.BackendWorker do
  use Honeydew
  import Logger, only: [log: 2]

  def init({st, port, hm}) do
    wid = :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
    sock = case :chumak.socket(:rep, String.to_charlist(wid)) do
             {:error, {:already_started, sockpid}} -> sockpid
             {:ok, sockpid} -> sockpid
             e ->
               log(:error, "#{inspect(e)} on chumak connect() received")
               nil
           end
    {:ok, _pid} = :chumak.connect(sock, :tcp, String.to_charlist(st[:host]), port)
    :timer.sleep(5)
    log(:info, "Starting backend worker #{inspect(wid)} on #{inspect(st[:host])}:#{inspect(port)}: HMAC = #{inspect(hm)}")
    st = Map.merge(st, %{ id: wid, sock: sock, hmac: hm})
    _pid = spawn_link(fn -> listener(sock, st) end)
    {:ok, st}
  end

  defp alg_from_keymap(%{ "crv" => "P-256", "kty" => "EC" }), do: "ES256"
  defp alg_from_keymap(_), do: nil

  defp do_sign(d, alg, %{kty: :jose_jwk_kty_rsa}, k), do: :public_key.sign({:digest, d}, alg, k)
  defp do_sign(d, alg, %{kty: :jose_jwk_kty_ec}, k), do: :public_key.sign({:digest, d}, alg, k)
  defp do_sign(d, alg, %{kty: :jose_jwk_kty_dsa}, k), do: :public_key.sign({:digest, d}, alg, k)
  defp do_sign(d, alg, %{kty: :jose_jwk_kty_okp_ed25519}, k), do: :jose_curve25519.ed25519_sign(d, k)

  defp command_reply("sign", %{ "keyname" => kname, "hash_type" => htype, "digest" => digest }, st ) do
    case get_in(st, [:keys, kname, "private"]) do
      nil ->
        Poison.encode!(%{ error: :unknown_key })
      km ->
        {kty, kk} = JOSE.JWK.from_map(km) |> JOSE.JWK.to_key
        alg = String.to_atom(htype)
        %{ payload: do_sign(digest, alg, kty, kk) |> Base.encode16(case: :lower) } |>
          Remsign.Utils.wrap("backend-key", "HS256", JOSE.JWK.from_oct(st[:hmac]))
    end
  end

  defp command_reply(c, _, _st) do
    log(:error, "Unknown command #{inspect(c)}")
    Poison.encode!(%{ error: :unknown_command })
  end

  defp handle_message(m, st) do
    msg = Remsign.Utils.unwrap(m,
      fn _k, :public -> JOSE.JWK.from_oct(st[:hmac]) end,
      st[:skew],
      fn n -> GenServer.call Remsign.Backend, {:store_nonce, n} end)
    command_reply(Map.get(msg, "command"), Map.get(msg, "parms"), st)
  end

  def listener(sock, st) do
    case :chumak.recv(sock) do
      {:ok, "ping"} ->
        log(:info, "Ping message received on #{st[:id]}")
        :chumak.send(sock, "pong")
      {:ok, m} ->
        rep = handle_message(m, st)
        :chumak.send(sock, rep)
      e ->
        log(:info, "Unknown message received on #{st[:id]}: #{inspect(e)}")
        :chumak.send(sock, Poison.encode(%{ error: :unknown_command }))
    end
    listener(sock, st)
  end
end
