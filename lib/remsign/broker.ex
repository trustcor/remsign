defmodule Remsign.Broker do
  import Logger, only: [log: 2]

  import Remsign.Pubkey, only: [keytype: 1]
  import Remsign.Server, only: [canonical_name: 1]

  @moduledoc """
  A broker GenServer which accepts registration from multiple backends,
  creates dealers for them, and which routes frontend signing requests
  to dealers capable of handling them
  """

  def init([]) do
    {:ok, %{dealers: %{}, keys: %{}}}
  end

  def start_link(_) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
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
