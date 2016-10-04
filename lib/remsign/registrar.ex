defmodule Remsign.Registrar do
  use GenServer

  import Logger, only: [log: 2]
  import Remsign.Utils, only: [get_in_default: 3]

  def init([cfg]) do
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
    {:ok, %{ sock: sock, pid: pid, listener: spawn_link(fn -> listener(sock) end) }}
  end

  def start_link(cfg = %{}) do
    GenServer.start_link __MODULE__, [cfg], name: __MODULE__
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

  def handle_cast({:message, "ping"}, st) do
    :chumak.send(st[:sock], "pong")
    {:noreply, st}
  end
end
