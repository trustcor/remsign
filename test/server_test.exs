defmodule RemsignServerTest do
  use ExUnit.Case

  setup do
    cfg = %{
      registrar: %{
        addr: "127.0.0.1",
        port: 25000
      }
    }
    [cfg: cfg]
  end

  test "bind registrar", ctx do
    {:ok, pid} = Remsign.Registrar.start_link( ctx[:cfg] )

    {:ok, sock} = :chumak.socket(:req, 'test-reg-ident')
    {:ok, _spid} = :chumak.connect(sock, :tcp, '127.0.0.1', 25000)
    assert :chumak.send(sock, "ping") == :ok
    case :chumak.recv(sock) do
      {:ok, msg} ->
        assert msg == "pong"
      e ->
        assert e == :fail
    end
  end

end
