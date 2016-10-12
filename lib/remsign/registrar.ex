defmodule Remsign.Registrar do
  use GenServer

  import Logger, only: [log: 2]
  import Remsign.Utils, only: [get_in_default: 3]

  def init([cfg, klf, nsf]) do
    {:ok, sock} = :chumak.socket(:rep)
    addr = get_in_default(cfg, [:registrar, :addr], "0.0.0.0") |> String.to_charlist
    port = get_in_default(cfg, [:registrar, :port], 19999)
    pid = case :chumak.bind(sock, :tcp, addr, port) do
            {:ok, spid} ->
              log(:debug, "Bound registrar to #{inspect(addr)}/#{inspect(port)}")
              spid
            e ->
              log(:error, "Unable to bind reply socket to #{inspect(addr)}:#{inspect(port)}: #{inspect(e)}")
              nil
          end
    {:ok, pa} = Agent.start_link(fn -> %{} end)
    {:ok, %{ sock: sock, pid: pid, listener: spawn_link(fn -> listener(sock) end),
             klf: klf, nsf: nsf,
             clock_skew: get_in_default(cfg, [:registrar, :clock_skew], 300),
             alg: get_in(cfg, [:registrar, :alg]),
             keyid: get_in(cfg, [:registrar, :keyid]),
             dealers: %{},
             k2d: %{},
             port_agent: pa,
             base_port: get_in_default(cfg, [:registrar, :base_port], 20000)
           }
    }
  end

  def start_link(cfg = %{}, klf, nsf) do
    GenServer.start_link __MODULE__, [cfg, klf, nsf], name: __MODULE__
  end

  defp listener(sock) do
    case :chumak.recv(sock) do
      {:ok, msg} ->
        GenServer.cast(__MODULE__, {:message, msg})
      e ->
        log(:warn, "Error on registrar receive: #{inspect(e)}")
    end
    listener(sock)
  end

  defp wrap(m), do: {:ok, m}

  defp jpeek(e = {:error, _}), do: e
  defp jpeek({:ok, jt}) do
    try do
      {:ok, Joken.peek(jt)}
    rescue
      ArgumentError -> {:error, :invalid_jwt}
    end
  end

  defp store_nonce(st, n), do: st[:nsf].(n)

  defp verify(e = {:error, _}, _, _), do: e
  defp verify({:ok, m}, k, alg) do
    m |>
      Joken.with_signer(
        %Joken.Signer{
          jws: %{ "alg" => alg },
          jwk: k
        }) |>
      Joken.verify
  end

  defp new_dealer(st, khash, pubkeys) do
    case Map.get(st[:dealers], khash) do
      nil ->
        log(:debug, "Creating new dealer for #{inspect(khash)}")
        {dport, dsock, _dpid} = Remsign.Dealer.alloc(%{ port_agent: st[:port_agent], base_port: st[:base_port] })
        d = Map.get(st, :dealers, %{}) |> Map.put(khash, {dport, dsock})
        kd = List.foldl(Map.keys(pubkeys), Map.get(st, :k2d, %{}), fn pk, m -> Map.put(m, pk, [{dport, dsock} | Map.get(m, pk, [])]) end)
        {Map.put(st, :dealers, d) |> Map.put(:k2d, kd), dport}
      {dport, _dsock } ->
        {st, dport}
    end
  end

  def command_reply(st, %{ "command" => "health" }) do
    {st, %{ command: :health, response: :ok }}
  end

  def command_reply(st, %{ "command" => "register", "params" => parms }) do
    pub = Map.get(parms, "ekey") |> JOSE.JWK.from_map
    pubkeys = Map.get(parms, "pubkeys", %{})
    khash = pubkeys |>
      Enum.map(fn {_kn, pubkey} -> Remsign.Pubkey.keyid(pubkey) end) |>
      Enum.reduce(<< >>, fn (kh,acc) -> :crypto.hash(:sha, acc <> kh) end)
    {st, dport} = new_dealer(st, khash, pubkeys)
    sk = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
    {:ok, plaintext} = Poison.encode(%{ hmac_key: sk, port: dport })
    {_alg, enc} = JOSE.JWE.block_encrypt(pub, plaintext, %{ "alg" => "RSA-OAEP", "enc" => "ChaCha20/Poly1305" })
    log(:debug, "Dealers = #{inspect(st[:dealers], pretty: true)}")
    log(:debug, "K2D = #{inspect(st[:k2d], pretty: true)}")
    {st, %{ command: :register, response: enc }}
  end

  def command_reply(st, p) do
    log(:warn, "Unknown command: #{inspect(p)}")
    {st, %{ error: :unknown_command }}
  end

  defp envelope(st, m) do
    %{ payload: m } |>
      Joken.token |>
      Joken.with_sub(st[:keyid]) |>
      Joken.with_iat(DateTime.utc_now) |>
      Joken.with_jti(Remsign.Utils.make_nonce) |>
      Joken.with_signer( %Joken.Signer{ jws: %{ "alg" => st[:alg] },
                                        jwk: st[:klf].(st[:keyid], :private) }) |>
      Joken.sign |>
      Joken.get_compact
  end

  def ping() do
    GenServer.call __MODULE__, {:send, "ping"}
  end

  def handle_message(st, m) do
    {:ok, jp} = Joken.token(m) |> wrap |> jpeek
    alg = case JOSE.JWS.peek_protected(m) |> Poison.decode do
            {:ok, %{ "alg" => algo }} -> algo
            _ -> "HS256" # default
          end
    k = st[:klf].(jp["sub"], :public)
    log(:debug, "Verification key #{inspect(jp["sub"])} = #{inspect(k, pretty: true)}")
    ver = Joken.token(m) |>
      Joken.with_validation("iat", fn t -> Remsign.Utils.validate_clock(t, st[:clock_skew]) end) |>
      Joken.with_validation("jti", fn n -> store_nonce(st, n) end) |>
      wrap |>
      verify(k, alg)
    case ver do
      %Joken.Token{error: nil} ->
        log(:debug, "Message verify => #{inspect(ver)}")
        {nst, rep} = command_reply(st, ver.claims)
        :chumak.send(st[:sock], envelope(st, rep))
        nst
      %Joken.Token{error: "Invalid signature"} ->
        :chumak.send(st[:sock], Poison.encode!(%{ error: :invalid_signature }))
        st
      %Joken.Token{error: "Invalid payload"} ->
        :chumak.send(st[:sock], Poison.encode!(%{ error: :invalid_payload }))
        st
    end
  end

  def handle_cast({:message, "ping"}, st) do
    :chumak.send(st[:sock], "pong")
    {:noreply, st}
  end

  def handle_cast({:message, m}, st) do
    jp = Joken.token(m) |> wrap |> jpeek
    st = case jp do
           {:ok, _dm} ->
             handle_message(st, m)
           {:error, e} ->
             :chumak.send(st[:sock], Poison.encode!(%{ error: e }))
             st
         end
    {:noreply, st}
  end

  def handle_call({:send, "ping"}, _from, st) do
    [d] = Enum.take_random(Map.keys(st[:dealers]), 1)
    log(:info, "Dealer is #{inspect(d)}")
    dsock = Map.get(st[:dealers], d) |> elem(1)

    :ok = :chumak.send_multipart(dsock, ["", "ping"])
    rep = case :chumak.recv_multipart(dsock) do
            {:ok, ["", "pong"]} ->
              "pong"
            e ->
              log(:info, "Reply to dealer socket: #{inspect(e)}")
              e
          end
    {:reply, rep, st}
  end

end
