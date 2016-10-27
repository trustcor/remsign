defmodule Remsign.Broker do
  import Logger, only: [log: 2]

  import Remsign.Pubkey, only: [keytype: 1]
  import Remsign.Server, only: [canonical_name: 1]

  @moduledoc """
  A broker GenServer which accepts registration from multiple backends,
  creates dealers for them, and which routes frontend signing requests
  to dealers capable of handling them
  """

  def init([%{ broker: bcfg}, klf ]) do
    {:ok, sock} = :chumak.socket(:router)
    case :chumak.bind(sock, :tcp, String.to_charlist(bcfg[:host]), bcfg[:port]) do
      {:ok, _bpid} ->
        st = %{ sock: sock,
                dealers: %{},
                klf: klf,
                skew: Map.get(bcfg, :skew, 60),
                cc: Map.get(bcfg, :cc, :nonce_cache)
              }
        log(:debug, "broker cfg = #{inspect(bcfg)}")
        spawn_link(fn -> listener(sock, st) end)
        {:ok, st}
      {:error, e} ->
        log(:error, "Unable to bind router socket to #{inspect(bcfg[:host])}:#{inspect(bcfg[:port])}: #{inspect(e)}")
        {:stop, :bind_error}
    end
      end

  def process_sign_message(sock, client, client_key, htype, digest, kid, st) do
    {hmk, res} = Remsign.Registrar.sign(kid, htype, digest)
    rep = case res do
      {:error, e} -> Poison.encode!(%{error: e})
      s when is_binary(s) ->
        case Poison.decode(s) do
          {:ok, _} -> s
          {:error, _} ->
            p = Remsign.Utils.unwrap(res, fn _k, :public -> hmk end,
            st[:skew],
            fn n -> Remsign.Utils.cc_store_nonce(st[:cc], n) end)

            sig = st[:klf].(client_key, "private") |> JOSE.JWK.from_map
            Remsign.Utils.wrap(%{ payload: p }, client_key, "HS256", sig)
        end
    end
    :chumak.send_multipart(sock, [client, "", rep])
  end

  def listener(sock, st) do
    case :chumak.recv_multipart(sock) do
      {:ok, [client, "", msg]} ->
        case valid_message?(msg, st) do
          {:ok, %{ "command" => "sign", "parms" => %{ "hash_type" => htype, "digest" => digest, "keyname" => kid } }, ck } ->
            spawn fn -> process_sign_message(sock, client, ck, htype, digest, kid, st) end
            :ok
          em = %{error: e} ->
            log(:error, "Malformed message : #{inspect(e)}")
            :chumak.send_multipart(sock, [client, "", Poison.encode!(em)])
        end
    end
    listener(sock, st)
  end

  def valid_message?(m, st) do
    client_key = Remsign.Utils.keyname(m)
    p = Remsign.Utils.unwrap(m, fn k, :public -> st[:klf].(k, "public") end,
      st[:skew],
      fn n -> Remsign.Utils.cc_store_nonce(st[:cc], n) end)
    case p do
      nil ->
        log(:error, "Unable to process message: #{inspect(m)}")
        %{ error: :malformed_command }
      c = %{ "command" => "sign" } ->
        {:ok, c, client_key}
      _ ->
        %{ error: :unknown_command }
    end
  end

  def start_link(cfg, klf) do
    GenServer.start_link(__MODULE__, [cfg, klf], name: __MODULE__)
  end

  def state() do
    GenServer.call __MODULE__, :state
  end

  def register(kval = %{}, cfg = %{}) do
    GenServer.call __MODULE__, {:register, kval, cfg}
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

  def terminate(reason, st) do
    log(:error, "Terminating broker: #{inspect(reason)}. State = #{inspect(st, pretty: true)}")
    :ok
  end
end
