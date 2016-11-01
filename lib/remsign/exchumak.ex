  defmodule ExChumak do
    use Application
    import Logger, only: [log: 2]

    def start(), do: start(:normal, [])

    def start(_type, _args) do
      ExChumakSuper.start_link()
    end

    def stop(_state), do: :ok

    def socket(type, identity) do
      ExChumakSuper.start_socket(type, identity)
    end

    def socket(type) do
      ExChumakSuper.start_socket(type)
    end

    def stop_socket(socketpid) do
      r = Supervisor.terminate_child(ExChumakSuper, socketpid)
      log(:info, "Stopping socket #{inspect(socketpid)}. Result = #{inspect(r)}")
    end

    def connect(socketpid, transport, host, port, resource)
     when is_pid(socketpid) and
          is_atom(transport) and
          is_list(host) and
          is_number(port) and
          is_list(resource) do

      GenServer.call(socketpid, {:connect, transport, host, port, resource})
    end

    def connect(socketpid, transport, host, port) do
      connect(socketpid, transport, host, port, [])
    end

    def bind(socketpid, transport, host, port) when
      is_pid(socketpid) and
      is_atom(transport) and
      is_list(host) and
      is_number(port) do
        GenServer.call(socketpid, {:bind, transport, host, port})
    end

    def send(socketpid, data) when  is_pid(socketpid) and
                                    is_binary(data) do
      GenServer.call(socketpid, {:send, data}, :infinity)
    end

    def send(socketpid, data) when  is_pid(socketpid) and
                                    is_list(data) do
      ExChumak.send(socketpid, to_string(data))
    end

    def send_multipart(socketpid, multipart) when is_pid(socketpid) and
                                                  is_list(multipart) do
      GenServer.call(socketpid, {:send_multipart, multipart}, :infinity)
    end

    def recv(socketpid) when is_pid(socketpid) do
      GenServer.call(socketpid, :recv, :infinity)
    end

    def recv_multipart(socketpid) when is_pid(socketpid) do
      GenServer.call(socketpid, :recv_multipart, :infinity)
    end

    def subscribe(socketpid, topic) when is_pid(socketpid) and is_binary(topic) do
      GenServer.cast(socketpid, {:subscribe, topic})
    end

    def subscribe(socketpid, topic) when is_pid(socketpid) and is_list(topic) do
      subscribe(socketpid, to_string(topic))
    end

    def cancel(socketpid, topic) when is_pid(socketpid) and is_binary(topic) do
      GenServer.cast(:socketpid, {:cancel, topic})
    end

    def cancel(socketpid, topic) when is_pid(socketpid) and is_list(topic) do
      cancel(socketpid, to_string(topic))
    end

    def resource() do
      ExChumakSuper.start_resource()
    end

    def attach_resource(resourcepid, resource, socketpid) do
      GenServer.cast(resourcepid, {:attach, resource, socketpid})
    end

    def version() do
      case Application.get_application(:chumak) do
        :chumak -> {:ok, return_version()}
        nil -> {:error, :application_not_started}
      end
    end

    def return_version() do
      Application.spec(:chumak, :vsn) |>
        to_string |>
        String.split(".", parts: 3) |>
        Enum.map(fn x -> Integer.parse(x) |> elem(0) end)
    end
  end

  defmodule ExChumakSuper do
    import Supervisor.Spec

    def start_link() do
      children = [
        worker(:chumak_socket, [], restart: :transient)
      ]
      {:ok, _sup_pid} = Supervisor.start_link(children, strategy: :simple_one_for_one, name: __MODULE__)
    end

    def start_socket(type, identity) do
      Supervisor.start_child(__MODULE__, [type, identity])
    end

    def start_socket(type) do
      :chumak_socket.start_link(type, [])
    end

    def start_resource() do
      :chumak_resource.start_link()
    end
  end
