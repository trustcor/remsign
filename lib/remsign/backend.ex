defmodule Remsign.Backend do
  @moduledoc """
  Functionality for a backend server, which gets registered to one or more
  brokers which then send signing requests to it.
  """
  use GenServer
  import Logger, only: [log: 2]

  def init([cfg = %{}, kl]) do
    sockname = to_string(cfg[:ident]) <> "." <> cfg[:host] <> "." <> to_string(cfg[:port])
    log(:debug, "Starting backend: #{sockname}")
    sock = case :chumak.socket(:req, String.to_charlist(sockname)) do
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
        nst = Map.merge(cfg, %{
                sock: sock,
                ekpriv: priv,
                ekpub: pub,
                kl: kl})
        {_r, dealers, be} = do_register(nst)
        {:ok, Map.put(nst, :backends, be) |> Map.put(:dealers, dealers)}
      e ->
        log(:error, "Non pong error from registrar: #{inspect(e)}")
        {:error, :no_registry_connect}
    end
  end

  def start_link(cfg = %{}, kl) do
    defaults = %{
      num_workers: 5,
      sock: nil,
      host: "127.0.0.1",
      port: 25000,
      ident: "backend",
      skew: 60,
      nstore: fn n -> Remsign.Utils.cc_store_nonce(:nonce_cache, n) end
    }
    GenServer.start_link __MODULE__, [ Map.merge(defaults, Remsign.Config.atomify(cfg)), kl ], name: __MODULE__
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

  defp do_register_h(_, nil, st) do
    log(:error, "Unable to load private signature key: #{st[:signkey]}")
    {nil, nil, nil}
  end

  defp do_register_h(msg, sigkey, st) do
    import Supervisor.Spec, warn: false

    log(:debug, "do_register_h: msg = #{inspect(msg)}, signature alg = #{st[:signalg]}")
    m = Remsign.Utils.wrap(msg, st[:signkey], st[:signalg], sigkey )
    log(:debug, "register message = #{inspect(m)}")
    :chumak.send(st[:sock],m)
    case :chumak.recv(st[:sock]) do
      {:ok, rep} ->
        rep2 = Remsign.Utils.unwrap(rep, fn k, _kt -> GenServer.call(st[:kl], {:lookup, k, :public}) end, st[:skew], st[:nstore])
        rep = handle_register_response(rep2, st)
        dealers = Enum.map(Map.get(rep, "dealers"),
          fn {kn, %{ "hmac" => kh, "port" => p}} ->
            {kn, case Base.decode16(kh, case: :mixed) do
              {:ok, k} -> {p, k}
              _ -> {nil, nil}
            end} end) |>
            Enum.reject(fn {_kn, {_p, k}} -> k == nil end) |>
            Enum.into(%{})

        children = Enum.map(1..st[:num_workers],
          fn n ->
            Supervisor.Spec.worker(Remsign.BackendWorker, [{st, dealers, n}], id: String.to_atom("Remsign.BackendWorker.#{n}"))
          end)
        Supervisor.start_link(children, strategy: :one_for_one)
        {rep, dealers, children}
      e ->
        log(:error, "Unexpected reply from register: #{inspect(e)}")
        {nil, nil, nil}
    end
  end

  def do_register(st) do
    msg = %{ command: "register",
             params: %{
               pubkeys: GenServer.call(st[:kl], :list_keys),
               ekey: st[:ekpub]
             }
           }
    sigkey = GenServer.call(st[:kl], {:lookup, st[:signkey], :private})
    do_register_h(msg, sigkey, st)
  end

  def hmac(kn) do
    GenServer.call(__MODULE__, {:hmac, kn})
  end

  def handle_call({:store_nonce, n}, _from, st) do
    {:reply, st[:nstore].(n), st}
  end

  def handle_call({:hmac, kn}, _from, st = %{ dealers: d = %{} }) do
    {:reply, Map.get(d, kn, {nil, nil}) |> elem(1), st}
  end
end

defmodule Remsign.BackendWorker do
  use GenServer

  import Logger, only: [log: 2]

  defp make_sock(host, port, hm) do
    wid = :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
    sock = case :chumak.socket(:rep, String.to_charlist(wid)) do
             {:error, {:already_started, sockpid}} -> sockpid
             {:ok, sockpid} -> sockpid
             e ->
               log(:error, "#{inspect(e)} on chumak connect() received")
               nil
           end
    {:ok, _pid} = :chumak.connect(sock, :tcp, String.to_charlist(host), port)
    :timer.sleep(5)
    {sock, hm, wid}
  end

  def init({st, dealers, n}) do
    socks = Enum.map(dealers, fn {kn, {port, k}} -> {kn, make_sock(st[:host], port, k)} end) |> Enum.into(%{})
    log(:info, "Starting backend worker #{inspect(n)} on #{inspect(socks)}")
    me = self
    _pids = Enum.map(socks, fn {_kn, {sock, k, wid}} -> spawn_link(fn -> listener(sock, k, wid, me, st) end) end)
    {:ok, Map.merge(st, %{socks: socks})}
  end

  def start_link({st, dealers, n}) do
    GenServer.start_link __MODULE__, {st, dealers, n}, name: String.to_atom("Remsign.BackendWorker.#{n}")
  end

  defp do_sign(d, alg, %{kty: :jose_jwk_kty_rsa}, k), do: :public_key.sign({:digest, d}, alg, k)
  defp do_sign(d, alg, %{kty: :jose_jwk_kty_ec}, k), do: :public_key.sign({:digest, d}, alg, k)
  defp do_sign(d, alg, %{kty: :jose_jwk_kty_dsa}, k), do: :public_key.sign({:digest, d}, alg, k)
  defp do_sign(d, _alg, %{kty: :jose_jwk_kty_okp_ed25519}, k), do: :jose_curve25519.ed25519_sign(d, k)

  defp command_reply("sign", %{ "keyname" => kname, "hash_type" => htype, "digest" => digest }, hm, st ) do
    case Remsign.Utils.known_hash(htype) do
      nil ->
        Poison.encode!(%{ error: :unknown_digest_type })
      alg when is_atom(alg) ->
        case GenServer.call(st[:kl], {:lookup, kname, :private}) do
          nil ->
            Poison.encode!(%{ error: :unknown_key })
          km ->
            log(:debug, "Decoding digest: #{inspect(digest)}")
            case Base.decode16(digest, case: :lower) do
              {:ok, d} ->
                {kty, kk} = JOSE.JWK.from_map(km) |> JOSE.JWK.to_key
                %{ payload: do_sign(d, alg, kty, kk) |> Base.encode16(case: :lower) } |>
                  Remsign.Utils.wrap("backend-key", "HS256", JOSE.JWK.from_oct(hm))
              :error ->
                Poison.encode!(%{error: :malformed_digest})
            end
        end
    end
  end

  defp command_reply(c, _, _, _st) do
    log(:error, "Unknown command #{inspect(c)}")
    Poison.encode!(%{ error: :unknown_command })
  end

  defp handle_message(m, hm, st) do
    msg = Remsign.Utils.unwrap(m,
      fn _k, :public -> JOSE.JWK.from_oct(hm) end,
      st[:skew],
      fn n -> GenServer.call Remsign.Backend, {:store_nonce, n} end)
    command_reply(Map.get(msg, "command"), Map.get(msg, "parms"), hm, st)
  end

  defp listener(sock, hm, wid, parent, st) do
    case :chumak.recv(sock) do
      {:ok, "ping"} ->
        log(:info, "Ping message received on #{wid}")
        send parent, {:reply, sock, "pong"}
      {:ok, m} ->
        send parent, {:reply, sock, handle_message(m, hm, st)}
      e ->
        log(:info, "Unknown message received on #{wid}: #{inspect(e)}")
        send parent, {:reply, sock, Poison.encode(%{ error: :unknown_command })}
    end
    listener(sock, hm, wid, parent, st)
  end

  def handle_info({:reply, sock, msg}, st) do
    :chumak.send(sock, msg)
    {:noreply, st}
  end
end
