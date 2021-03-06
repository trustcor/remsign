  defmodule Remsign.Backend do
    @moduledoc """
    Functionality for a backend server, which gets registered to one or more
    brokers which then send signing requests to it.
    """
    use GenServer
    import Logger, only: [log: 2]
    import Remsign.Utils, only: [get_in_default: 3]

    def init([cfg = %{}, kl]) do
      sockname = to_string(cfg[:ident]) <> "." <> cfg[:host] <> "." <> to_string(cfg[:port])
      log(:debug, "Starting backend: #{sockname}")
      sock = case ExChumak.socket(:req, String.to_charlist(sockname)) do
               {:error, {:already_started, sockpid}} -> sockpid
               {:ok, sockpid} -> sockpid
               e ->
                 log(:error, "#{inspect(e)} on chumak connect() received")
                 nil
             end
      {pub, priv} = Remsign.Utils.generate_rsa(Map.get(cfg, :modulus_size, 2048))
      {:ok, _pid} = ExChumak.connect(sock, :tcp, String.to_charlist(cfg[:host]), cfg[:port])
      ExChumak.send(sock, "ping")
      case ExChumak.recv(sock) do
        {:ok, "pong"} ->
          nst = Map.merge(cfg, %{
                  sock: sock,
                  ekpriv: priv,
                  ekpub: pub,
                  kl: kl})
          GenServer.call(kl, {:set_backend, self})
          {_r, dealers, be, sup} = do_register(nst)
          me = self
          ppid = spawn_link(fn -> pinger(me, sock, get_in_default(cfg, [:timeout], 1000)) end)
          {:ok,
            Map.put(nst, :backends, be) |>
              Map.put(:dealers, dealers) |>
              Map.put(:supervisor, sup) |>
              Map.put(:pinger, ppid)}
        e ->
          log(:error, "Non pong error from registrar: #{inspect(e)}")
          {:error, :no_registry_connect}
      end
    end

    defp ping(parent, sock) do
      case ExChumak.send(sock, "ping") do
        :ok ->
          case ExChumak.recv(sock) do
            {:ok, "pong"} ->
              send parent, :ok
            _ ->
              send parent, :error
          end
        _ ->
          send parent, :error
      end

    end

    defp pinger(parent, sock, timeout) do
      me = self
      spawn fn -> ping(me, sock) end
      continue = receive do
        :ok ->
          send parent, :ping_ok
          :cont
        :error ->
          send parent, :ping_error
          :stop
        :stop ->
          :stop
      after
        timeout ->
          send parent, :ping_timeout
          :stop
      end

      case continue do
        :cont ->
          :timer.sleep(500)
          pinger(parent, sock, timeout)
        :stop ->
          :ok
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
      GenServer.start_link __MODULE__, [ Map.merge(defaults, Remsign.Config.atomify(cfg)), kl ], name: String.to_atom(cfg[:ident])
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
      ExChumak.send(st[:sock],m)
      case ExChumak.recv(st[:sock]) do
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
              Supervisor.Spec.worker(Remsign.BackendWorker, [{st, dealers, n}],
                id: String.to_atom("Remsign.BackendWorker.#{n}"))
            end)
          {:ok, sup} = Supervisor.start_link(children, strategy: :one_for_one,
            restart: :transient)
          {rep, dealers, children, sup}
        e ->
          log(:error, "Unexpected reply from register: #{inspect(e)}")
          {nil, nil, nil, nil}
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

    defp handle_add_key_response(%{ "command" => "add_key", "response" => resp = %{ "ciphertext" => _ } }, st) do
      alg = %{alg: :jose_jwe_alg_rsa, enc: :jose_jwe_enc_chacha20_poly1305}
      {pt, _m} = JOSE.JWE.block_decrypt(JOSE.JWK.from_map(st[:ekpriv]), {alg, resp})
      case Poison.decode(pt) do
        {:ok, m = %{}} -> Map.put(m, "command", "add_key")
        _ -> {:error, :malformed_response}
      end
    end

    defp handle_add_key_response(_, _st) do
      { :error, :malformed_response }
    end

    defp do_add_key_h(_, nil, st) do
      log(:error, "Unable to load private signature key: #{st[:signkey]}")
      nil
    end

    defp do_add_key_h(msg, sigkey, st) do
      m = Remsign.Utils.wrap(msg, st[:signkey], st[:signalg], sigkey)
      ExChumak.send(st[:sock], m)
      case ExChumak.recv(st[:sock]) do
        {:ok, rep} ->
          rep2 =  Remsign.Utils.unwrap(rep, fn k, _kt -> GenServer.call(st[:kl], {:lookup, k, :public}) end, st[:skew], st[:nstore])
          case handle_add_key_response(rep2, st) do
            %{ "command" => "add_key", "dealer" => %{ "port" => port, "hmac" => kh }} ->
              case Base.decode16(kh, case: :mixed) do
                {:ok, k} ->
                  kn = get_in(msg, [:params, :name])
                  log(:debug, "Port for kn #{kn} port = #{port}, hmac = #{inspect(k)}")
                  Enum.each(Supervisor.which_children(st[:supervisor]),
                    fn {_, cpid, _, _} -> GenServer.call(cpid, {:add_dealer, kn, port, k}) end)
                _ -> nil
              end
            e ->
              log(:error, "Add key response yields unexpected reply: #{inspect(e)}")
              nil
          end
        e ->
          log(:error, "Unexpected reply from add_key recv: #{inspect(e)}")
          nil
      end
    end

    def do_add_key(kn, pk, st) do
      msg = %{ command: "add_key",
               params: %{
                 name: kn,
                 pubkey: pk,
                 ekey: st[:ekpub]
              }
            }
     log(:debug, "Looking up signing key #{st[:signkey]}")
     sigkey = GenServer.call(st[:kl], {:lookup, st[:signkey], :private})
     log(:debug, "Signing add_key with #{inspect(sigkey)}")

     do_add_key_h(msg, sigkey, st)
    end

    def hmac(be, kn) do
      GenServer.call(be, {:hmac, kn})
    end

    def handle_call({:store_nonce, n}, _from, st) do
      {:reply, st[:nstore].(n), st}
    end

    def handle_call({:hmac, kn}, _from, st = %{ dealers: d = %{} }) do
      {:reply, Map.get(d, kn, {nil, nil}) |> elem(1), st}
    end

    def handle_call({:add_key, kn, pk}, _from, st) when is_binary(kn) do
      log(:debug, "Adding key #{kn}")
      {:reply, do_add_key(kn, pk, st), st}
    end

    def handle_call({:del_key, kn}, _from, st) when is_binary(kn) do
      log(:debug, "Deleting key #{kn}")
      {:reply, :ok, st}
    end

    def handle_info(:ping_ok, st) do
      # do nothing
      {:noreply, st}
    end

    def handle_info(:ping_error, st) do
      log(:error, "Backend #{st[:ident]} ping returns error")
      {:stop, :shutdown, st}
    end

    def handle_info(:ping_timeout, st) do
      log(:error, "Backend ping #{st[:ident]} to broker has timed out")
      children = Supervisor.which_children(st[:supervisor])
      log(:error, "Backend workers = #{inspect(children)}")
      sr = Enum.map(children,
        fn {_, cpid, _, _} -> GenServer.call(cpid, :killme) end)
      log(:error, "Stop children results = #{inspect(sr)}")
      {:stop, :shutdown, st}
    end

    def terminate(reason, st) do
      log(:error, "Backend #{st[:ident]} terminating: #{inspect(reason)}")
      :shutdown
    end
  end

  defmodule Remsign.BackendWorker do
    use GenServer

    import Logger, only: [log: 2]

    defp make_sock(host, port, hm) do
      wid = :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
      sock = case ExChumak.socket(:rep, String.to_charlist(wid)) do
               {:error, {:already_started, sockpid}} -> sockpid
               {:ok, sockpid} -> sockpid
               e ->
                 log(:error, "#{inspect(e)} on chumak connect() received")
                 nil
             end
      case ExChumak.connect(sock, :tcp, String.to_charlist(host), port) do
        {:ok, _pid} ->
          log(:info, "Backend worker connected to port #{port}")
          :ok
        e ->
          log(:error, "Worker unable to connect to #{inspect(host)}:#{port}: #{inspect(e)}")
          nil
      end
      :timer.sleep(5)
      {sock, hm, wid}
    end

    def init({st, dealers, n}) do
      socks = Enum.map(dealers, fn {kn, {port, k}} -> {kn, make_sock(st[:host], port, k)} end) |> Enum.into(%{})
      log(:debug, "Starting backend worker #{inspect(n)} on #{inspect(socks)}")
      me = self
      _pids = Enum.map(socks, fn {_kn, {sock, k, wid}} -> spawn(fn -> listener(sock, k, wid, me, st) end) end)
      {:ok, Map.merge(st, %{socks: socks, parent: me, ident: n})}
    end

    def start_link({st, dealers, n}) do
      GenServer.start_link __MODULE__, {st, dealers, n}, name: String.to_atom("Remsign.BackendWorker.#{st[:ident]}.#{n}")
    end

    defp do_sign(d, alg, %{kty: :jose_jwk_kty_rsa}, k), do: :public_key.sign({:digest, d}, alg, k)
    defp do_sign(d, alg, %{kty: :jose_jwk_kty_ec}, k), do: :public_key.sign({:digest, d}, alg, k)
    defp do_sign(d, alg, %{kty: :jose_jwk_kty_dsa}, k), do: :public_key.sign({:digest, d}, alg, k)
    defp do_sign(d, _alg, %{kty: :jose_jwk_kty_okp_ed25519}, k), do: :jose_curve25519.ed25519_sign(d, k)

    defp command_reply("sign", %{ "keyname" => kname, "hash_type" => htype, "digest" => digest }, hm, st ) do
      log(:debug, "Got sign request for #{inspect(kname)}")
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
        st[:skew], fn n -> st[:nstore].(n) end)
      command_reply(Map.get(msg, "command"), Map.get(msg, "parms"), hm, st)
    end

    defp listener(sock, hm, wid, parent, st) do
      case ExChumak.recv(sock) do
        {:ok, "ping"} ->
          log(:debug, "Ping message received on #{wid}")
          send parent, {:reply, sock, "pong"}
        {:ok, m} ->
          send parent, {:reply, sock, handle_message(m, hm, st)}
        e ->
          log(:warn, "Unknown message received on #{wid}: #{inspect(e)}")
          send parent, {:reply, sock, Poison.encode(%{ error: :unknown_command })}
      end
      listener(sock, hm, wid, parent, st)
    end

    def handle_info({:reply, sock, msg}, st) do
      ExChumak.send(sock, msg)
      {:noreply, st}
    end

    def handle_call(:killme, from, st) do
      log(:info, "Killme called: #{inspect(st[:socks])}")
      r = Enum.map(st[:socks], fn {kn, {sock, _hm, _wid}} -> log(:info, "Requesting stop on #{inspect(sock)}/#{kn}"); ExChumak.stop_socket(sock) end)
      log(:info, "Killing backend worker #{st[:ident]} by request from backend #{inspect(from)}: socket results: #{inspect(r)}")
      {:reply, r, st}
    end

    def handle_call({:add_dealer, kn, port, hm}, _from, st) do
      {sock, hm, wid} = make_sock(st[:host], port, hm)
      spawn_link(fn -> listener(sock, hm, wid, st[:parent], st) end)
      {:reply, :ok, Map.put(st, :socks, Map.put(st[:socks], kn, sock))}
    end

    def terminate(reason, st) do
      log(:error, "Backend Worker #{st[:ident]} terminating: #{inspect(reason)}")
      :shutdown
    end
  end
