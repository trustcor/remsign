defmodule Remsign.Broker do
  import Logger, only: [log: 2]

  import Remsign.Pubkey, only: [keytype: 1]
  import Remsign.Server, only: [canonical_name: 1]

  @moduledoc """
  A broker GenServer which accepts registration from multiple backends,
  creates dealers for them, and which routes frontend signing requests
  to dealers capable of handling them
  """

  def init([cfg = %{ broker: bcfg } ]) do
    {:ok, sock} = :chumak.socket(:router)
    case :chumak.bind(sock, :tcp, String.to_charlist(bcfg[:host]), bcfg[:port]) do
      {:ok, _bpid} ->
        st = %{ sock: sock,
                dealers: %{},
                keys: Map.get(bcfg, :keys, %{}),
                skew: Map.get(bcfg, :skew, 60),
                cc: Map.get(bcfg, :cc)
              }
        log(:debug, "broker cfg = #{inspect(bcfg)}")
        spawn_link(fn -> listener(sock, st) end)
        {:ok, st}
      {:error, e} ->
        log(:error, "Unable to bind router socket to #{inspect(bcfg[:host])}:#{inspect(bcfg[:port])}: #{inspect(e)}")
        {:stop, :bind_error}
    end
  end

  def listener(sock, st) do
    case :chumak.recv_multipart(sock) do
      {:ok, [client, "", msg]} ->
        case valid_message?(msg, st) do
          {:ok, c = %{ "command" => "sign", "parms" => %{ "hash_type" => htype, "digest" => digest, "keyname" => kid } } } ->
            {hmk, res} = Remsign.Registrar.sign(kid, htype, digest)
            p = Remsign.Utils.unwrap(res,
              fn _k, :public -> hmk end,
              st[:skew],
            fn n ->
              log(:debug, "Checking nonce #{inspect(n)}")
              Remsign.Utils.cc_store_nonce(st[:cc], n) end)
            sig = Remsign.Broker.key() |> JOSE.JWK.from_map
            rep = Remsign.Utils.wrap(%{ payload: p }, kid, "HS256", sig)
            :chumak.send_multipart(sock, [client, "", rep])
          em = %{error: e} ->
            log(:error, "Malformed message : #{inspect(e)}")
            :chumak.send_multipart(sock, [client, "", Poison.encode!(em)])
        end
    end
    listener(sock, st)
  end

  def valid_message?(m, st) do
    p = Remsign.Utils.unwrap(m, fn k, :public -> get_in(st, [:keys, k]) end,
      st[:skew],
      fn n -> Remsign.Utils.cc_store_nonce(st[:cc], n) end)
    case p do
      nil ->
        log(:error, "Unable to process message: #{inspect(m)}")
        %{ error: :malformed_command }
      c = %{ "command" => "sign" } ->
        {:ok, c}
      _ ->
        %{ error: :unknown_command }
    end
  end

  def start_link(cfg) do
    GenServer.start_link(__MODULE__, [cfg], name: __MODULE__)
  end

  def state() do
    GenServer.call __MODULE__, :state
  end

  def register(kval = %{}, cfg = %{}) do
    GenServer.call __MODULE__, {:register, kval, cfg}
  end

  def key() do
    GenServer.call __MODULE__, :key
  end

  defp add_to_keyval(k = %{}, kval, v) do
    kt = keytype(kval)
    kid = canonical_name(kval)
    case Map.get(k, kt) do
      nil -> Map.put(k, kt, %{ kid => v })
      m -> Map.put(k, kt, Map.put(m, kid, v))
    end
  end

  defp add_to_dealer(d = %{}, rs, v) do
    Map.put(d, rs,
      case Map.get(d, rs) do
        nil -> MapSet.new([v])
        ms -> MapSet.put(ms, v)
      end )
  end

  def handle_call(:state, _from, st) do
    {:reply, st, st}
  end

  def handle_call({:register, kval, cfg}, _from, st) do
    d = Map.get(st, :dealers, %{})
    k = Map.get(st, :keys, %{})
    kt = keytype(kval)
    kid = canonical_name(kval)
    {:reply, :ok,
     case get_in(k, [kt, kid]) do
       %Remsign.Server{name: _rsn, dealer_port: _dp} ->
         st
       _kv ->
         rs = Remsign.Server.new(kval, cfg)
         d = add_to_dealer(d, rs, kval)
         k = add_to_keyval(k, kval, rs)
         Map.put(st, :dealers, d) |> Map.put(:keys, k)
     end
    }
  end

  def handle_call(:key, _from, st) do
    {:reply, get_in(st, [:keys, "fe-key"]), st}
  end

  def terminate(reason, st) do
    log(:error, "Terminating broker: #{inspect(reason)}. State = #{inspect(st, pretty: true)}")
    :ok
  end
end
