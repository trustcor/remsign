defmodule Remsign.Dealer do
  @moduledoc """
  This module maintains a pool of dealers which have advertised a given
  key set. Backend signers then connect to these dealers to receive signing
  requests from clients, which submit requests to the brokers.
  """
  import Logger, only: [log: 2]

  defp allocate_port(nil, _) do
    log(:error, "Port allocation agent not running")
    nil
  end

  defp allocate_port(ag, base_port) do
    aport = Agent.get_and_update(ag,
      fn m -> {Map.get(m, :port, base_port),
               Map.put(m, :port, Map.get(m, :port, base_port) + 1)} end)
    aport
  end

  def alloc(cfg = %{}) do
    p = allocate_port(Map.get(cfg, :port_agent), Map.get(cfg, :base_port, 20000))
    case ExChumak.socket(:dealer) do
      {:ok, dsock} ->
        case :chumak.bind(dsock, :tcp,
              Map.get(cfg, :bind_addr, "0.0.0.0") |> String.to_charlist,
              p) do
          {:ok, dpid} ->
            log(:debug, "Dealer socket bound to port #{p}")
            {p, dsock, dpid}
          e ->
            log(:warn, "Unable to bind to port #{p}: #{inspect(e)}")
            nil
        end
      e ->
        log(:warn, "Unable to create dealer socket: #{inspect(e)}")
        nil
    end
  end

end
