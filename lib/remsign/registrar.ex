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
    {:ok, %{ sock: sock, pid: pid, listener: spawn_link(fn -> listener(sock) end),
             klf: klf, nsf: nsf,
             clock_skew: get_in_default(cfg, [:registrar, :clock_skew], 300)
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

  defp validate_clock(t, skew) do
    case Timex.parse(t, "{ISO:Extended:Z}") do
      {:ok, ts} ->
        abs(Timex.diff(DateTime.utc_now, ts, :seconds)) < skew
      {:error, e} ->
        log(:error, "Timestamp format for #{inspect(t)} invalid: #{inspect(e)}")
        false
    end
  end

  defp store_nonce(st, n), do: st[:nsf].(n)

  defp verify(e = {:error, _}, _, _), do: e
  defp verify({:ok, m}, k, alg) do
    m |>
      Joken.with_signer(
        %Joken.Signer{
          jws: %{ "alg" => alg },
          jwk: k["public"]
        }) |>
      Joken.verify
  end

  def handle_cast({:message, "ping"}, st) do
    :chumak.send(st[:sock], "pong")
    {:noreply, st}
  end

  def handle_cast({:message, m}, st) do
    jp = Joken.token(m) |> wrap |> jpeek
    case jp do
      {:ok, _dm} -> handle_message(st, m)
      {:error, e} ->
        :chumak.send(st[:sock], Poison.encode!(%{ error: e }))
    end
    {:noreply, st}
  end

  def handle_message(st, m) do
    {:ok, jp} = Joken.token(m) |> wrap |> jpeek
    alg = case JOSE.JWS.peek_protected(m) |> Poison.decode do
            {:ok, %{ "alg" => algo }} -> algo
            _ -> "HS256" # default
          end
    k = st[:klf].(jp["sub"])
    ver = Joken.token(m) |>
      Joken.with_validation("iat", fn t -> validate_clock(t, st[:clock_skew]) end) |>
      Joken.with_validation("jti", fn n -> store_nonce(st, n) end) |>
      wrap |>
      verify(k, alg)
    case ver do
      %Joken.Token{error: nil} ->
        log(:info, "Message is #{inspect(jp["payload"])} verify => #{inspect(ver)}")
        :chumak.send(st[:sock], Poison.encode!(%{ error: :unknown_command }))
      %Joken.Token{error: "Invalid signature"} ->
        :chumak.send(st[:sock], Poison.encode!(%{ error: :invalid_signature }))
      %Joken.Token{error: "Invalid payload"} ->
        :chumak.send(st[:sock], Poison.encode!(%{ error: :invalid_payload }))
    end
  end
end
