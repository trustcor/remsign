defmodule Remsign do
  use Application
  import Logger, only: [log: 2]
  import Remsign.Utils, only: [get_in_default: 3]

  defp gate({t, g, f}) when is_map(g) and is_atom(t) do
    if Map.has_key?(g, t) do
      log(:info, "#{t}: Starting gated worker with #{inspect(g)}")
      f.(g)
    else
      log(:info, "#{t}: Skipping gated worker. No #{inspect(t)} entry in config map")
      nil
    end
  end
  defp gate(f), do: f

  defp store_nonce(n, ttl), do: Remsign.Utils.cc_store_nonce(:nonce_cache, n, ttl)

  defp find_key(keys, keyid, :private), do: find_key(keys, keyid, "private")
  defp find_key(keys, keyid, :public), do: find_key(keys, keyid, "public")
  defp find_key(keys, keyid, type) do
    case Enum.find(keys, fn %{ "name" => n } -> keyid == n end) do
      nil -> nil
      k -> Map.get(k, type)
    end
  end

  defp backend_name(cfg) do
    String.to_atom(to_string(cfg["ident"]) <> "." <> cfg["host"] <> "." <> to_string(cfg["port"]))
  end

  def bstart(), do: start(:normal, "/usr/local/remsign-backend/remsign.yml")
  def dstart(), do: start(:normal, "/usr/local/remsign/remsign.yml")
  def tstart(), do: start(:normal, "test/config.yml")

  def tsign(), do: Remsign.Frontend.sign("key1", "sha", "Test Sign")

  def start(type), do: start(type, %{})

  def start(type, cfile) when is_binary(cfile) do
    start(type, Remsign.Config.config_yaml_file(cfile))
  end

  def start(_type, cfg) when is_map(cfg) do
    import Supervisor.Spec, warn: false

    skew = Map.get(cfg, :skew, 30)
    ttl = 2 * skew
    keys = Remsign.Keylookup.find_control_files(
      get_in_default(cfg, [:keys, :directory], "keys"),
      fn x -> Remsign.Keylookup.read_yaml_file(x) end,
      get_in_default(cfg, [:keys, :extensions], [".yml"]))

    children = [
      worker(ConCache, [[ttl_check: :timer.seconds(5), ttl: :timer.seconds(ttl)], [name: :nonce_cache]]),
      worker(Remsign.FileKeyLookup, [get_in_default(cfg, [:keys, :directory], "keys"),
                                     get_in_default(cfg, [:keys, :extensions], [".yml"])]),
      {:broker, cfg, fn _c -> worker(Remsign.Broker, [cfg, fn kn, t -> find_key(keys, kn, t) end]) end},
      {:registrar, cfg, fn _c -> worker(Remsign.Registrar, [cfg,
                                                            &Remsign.FileKeyLookup.lookup/2,
                                                            fn n -> store_nonce(n, ttl) end]) end},
      {:frontend, cfg, fn _c -> worker(Remsign.Frontend, [cfg]) end},
      Enum.map(Map.get(cfg, :backend, []), fn b -> worker(Remsign.Backend,
       [Remsign.Config.atomify(b), Remsign.FileKeyLookup],
       id: backend_name(b)) end)
    ] |>
      List.flatten |>
      Enum.map(&gate/1) |>
      Enum.reject(fn x -> x == nil end)
    opts = [strategy: :one_for_one, name: Remsign.Supervisor]
    Supervisor.start_link(children, opts)
  end

end
