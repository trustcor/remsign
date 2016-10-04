defmodule Remsign do
  use Application
  import Logger, only: [log: 2]

  def start do
    start(:normal, 10)
  end

  def start(_type, num_workers) do
    import Supervisor.Spec, warn: false
    {:ok, a} = Agent.start_link(fn -> 0 end, name: __MODULE__)
    children = [
      Honeydew.child_spec(:remsign_pool, Remsign.Client, {'ci-vm.shared', 5555, a}, workers: num_workers)
    ]

    Supervisor.start_link(children, strategy: :one_for_one)
  end

  def do_call(batch, batchsize) do
    Enum.map(1..batchsize, fn n -> Task.async(fn -> Remsign.Client.call(:remsign_pool, {:get, [batch * batchsize + n]}) end) end) |>
    Enum.map(&Task.await(&1))
  end

  def run(batchsize \\ 10) do
    iters = 10000
    nbatches = trunc((iters / batchsize) - 1)
    {eltime, _v} = :timer.tc( fn ->
      Enum.map(0..nbatches, fn batch -> do_call(batch, batchsize) end)
    end)
    eltime / 1000000.0
  end
end

defmodule Remsign.Client do
  import Logger, only: [log: 2]
  use Honeydew

  def init({ip, port, a}) do
    n = Agent.get_and_update(a, fn i -> {i, i + 1} end)
    ident = "req-#{n}"
    {:ok, sock} = :chumak.socket(:req, String.to_charlist(ident))
    case :chumak.connect(sock, :tcp, ip, port) do
      {:ok, pid} ->
        log(:info, "Connected #{inspect(pid)} to socket #{inspect(sock)}")
      {:error, e} ->
        log(:error, "Unable to connect to socket: #{inspect(e)}")
      e ->
        log(:error, "Unexpected reply from connect: #{inspect(e)}")
    end
    {:ok, {sock, ident}}
  end

  def get(i, {sock, ident}) do
    req = "client-#{i}-#{ident}"
    :chumak.send(sock, req)
    case :chumak.recv(sock) do
      {:ok, r} ->
        log(:info, "Got reply: #{inspect(r)}")
      e ->
        log(:warn, "Error: #{inspect(e)}")
    end
  end
end

defmodule Remsign.TServerSup do
  import Logger, only: [log: 2]

  def start do
    start(:normal, 10)
  end

  def start(_type, num_workers) do
    import Supervisor.Spec, warn: false

    {:ok, a} = Agent.start_link(fn -> %{num: 0, servers: %{}}  end, name: __MODULE__)
    {:ok, fsock} = :chumak.socket(:router)
    case :chumak.bind(fsock, :tcp, '0.0.0.0', 5555) do
      {:ok, bpid} ->
        log(:info, "Bound with pid #{inspect(bpid)}, socket #{inspect(fsock)}")
      {:error, e} ->
        log(:error, "Unable to bind to socket: #{inspect(e)}")
      e ->
        log(:error, "Unexpected reply from bind: #{inspect(e)}")
    end
    {:ok, bsock} = :chumak.socket(:dealer)
    case :chumak.bind(bsock, :tcp, 'localhost', 5556) do
      {:ok, bpid} ->
        log(:info, "Bound with pid #{inspect(bpid)}, socket #{inspect(bsock)}")
      {:error, e} ->
        log(:error, "Unable to bind to socket: #{inspect(e)}")
      e ->
        log(:error, "Unexpected reply from bind: #{inspect(e)}")
    end
    spawn_link(fn -> floop(fsock,bsock,"->") end)
    spawn_link(fn -> bloop(fsock,bsock,"<-") end)

    children = Enum.map(1..num_workers, fn i -> worker(Remsign.TServer, [a], id: String.to_atom("Remsign.TServer.#{i}")) end)
    r = Supervisor.start_link(children, strategy: :one_for_one)

    servers = Agent.get(a, fn m -> Map.values(m[:servers]) end)
    Enum.map(servers, fn s -> spawn_link(fn -> server_loop(s) end) end)
    r
  end

  defp listen(sock, ident) do
    case :chumak.recv(sock) do
      {:ok, mp} ->
        log(:info, "Received data #{inspect(mp)}")
        [cident, msg] = String.split(mp, "|", parts: 2)
        delay = Enum.reduce(1..10, 0, fn _i, acc -> :rand.uniform(10) + acc end)
        :timer.sleep(delay)
        reply = "#{cident}|Hello #{msg} from worker #{ident}"
        :chumak.send(sock, reply)
      e ->
        log(:error, "Error on receive: #{inspect(e)}")
    end
    listen(sock, ident)
  end

  def server_loop(s) do
    {sock, ident} = Remsign.TServer.id(s)
    listen(sock, ident)
  end

  def floop(fsock,bsock,dir) do
    case :chumak.recv_multipart(fsock) do
      {:ok, [ident, "", msg]} ->
        log(:info, "#{dir} #{ident} #{inspect(msg)}")
        :chumak.send_multipart(bsock, ["", to_string(ident) <> "|" <> msg])
      e ->
        log(:error, "floop error #{inspect(e)}")
    end
    floop(fsock,bsock,dir)
  end

  def bloop(fsock,bsock,dir) do
    case :chumak.recv_multipart(bsock) do
      {:ok, ["", msgmp]} ->
        log(:info, "#{dir} #{inspect(msgmp)}")
        [cident,msg] = String.split(msgmp, "|", parts: 2)
        :chumak.send_multipart(fsock, [cident, "", msg])
      e ->
        log(:error, "bloop error #{inspect(e)}")
    end
    bloop(fsock,bsock,dir)
  end
end

defmodule Remsign.TServer do
  import Logger, only: [log: 2]
  use GenServer

  def init(ident) do
    {:ok, sock} = :chumak.socket(:rep, ident)
    {:ok, _ppid} = :chumak.connect(sock, :tcp, 'localhost', 5556)
    log(:info, "Server #{ident} connected to backend")
    {:ok, {sock, ident}}
  end

  def start_link(a) do
    n = Agent.get_and_update(a, fn m -> {m[:num], Map.put(m, :num, m[:num] + 1)} end)
    idents = "server-#{n}"
    ident = String.to_charlist(idents)
    myname = String.to_atom(to_string(__MODULE__) <> "." <> to_string(n))
    Agent.update(a, fn m -> put_in(m, [:servers, n], myname) end)
    GenServer.start_link __MODULE__, ident, name: myname
  end

  def id(s) do
    GenServer.call s, :id
  end

  def handle_call(:id, _from, {sock, ident}) do
    {:reply, {sock, ident}, {sock, ident}}
  end
end
