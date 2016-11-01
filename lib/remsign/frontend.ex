defmodule Remsign.Frontend do
  @moduledoc """
  GenServer implementation which connects to multiple brokers and
  issues and processes signing requests to them.
  """

  import Logger, only: [log: 2]
  import Remsign.Utils, only: [get_in_default: 3]

  use GenServer

  def init([cfg]) do
    keys = Remsign.Keylookup.find_control_files(get_in(cfg, [:keys, :directory]), fn x -> Remsign.Keylookup.read_yaml_file(x) end )

    children = [
      Honeydew.child_spec(:frontend_pool, Remsign.FrontendPool,
        {
          get_in_default(cfg, [:frontend, :brokers], []),
          keys,
          get_in_default(cfg, [:frontend, :keyid], "remsign-client-key"),
          get_in_default(cfg, [:frontend, :skew], 30),
          get_in_default(cfg, [:frontend, :timeout], 1000),
          get_in_default(cfg, [:frontend, :tries], 3)
          })]

    bs = broker_state(get_in_default(cfg, [:frontend, :brokers], []))
    log(:info, "Broker state = #{inspect(bs, pretty: true)}")
    {:ok, %{  super: Supervisor.start_link(children, strategy: :one_for_one),
              bstate: bs,
              purge_timeout: get_in_default(cfg, [:frontend, :fail_expiry], 1800),
              tries: get_in_default(cfg, [:frontend, :tries], 3)
            }
           }
  end

  defp broker_state(brokers) do
    Enum.map(brokers,
      fn %{ "host" => h, "port" => p} -> {"#{h}:#{p}", %{ failts: []}}
        _ -> nil
    end) |>
    Enum.reject(fn x -> x == nil end) |>
    Enum.into(%{})
  end

  def start_link(cfg) do
    GenServer.start_link __MODULE__, [cfg], name: __MODULE__
  end

  defp sign_h(_, nil, _), do: {:error, :unknown_digest_type}
  defp sign_h(keyid, htype, digest) when is_binary(keyid) and is_atom(htype) and is_binary(digest) do
    Remsign.FrontendPool.call(:frontend_pool, {:sign, [keyid, htype, digest]})
  end

  defp sign_m(keyid, htype, message) do
    d = :crypto.hash(htype, message) |> Base.encode16(case: :lower)
    sign_h(keyid, htype, d)
  end

  def dsign(keyid, hash_type, digest), do:  sign_h(keyid, Remsign.Utils.known_hash(hash_type), digest)
  def sign(keyid, hash_type, message), do: sign_m(keyid, Remsign.Utils.known_hash(hash_type), message)

  def dsign_async(keyid, hash_type, digest), do: Task.async(fn -> sign_h(keyid, Remsign.Utils.known_hash(hash_type), digest) end)
  def sign_async(keyid, hash_type, message), do: Task.async(fn -> sign_m(keyid, Remsign.Utils.known_hash(hash_type), message) end)

  defp purge_fail_ts(fts, expiret) do
    # clear out any timestamps from the failure list which are older than
    # 'expiret' (expressed in seconds)
    ets = (DateTime.utc_now() |> DateTime.to_unix()) - expiret
    Enum.filter(fts, fn ts -> ts >= ets end)
  end

  defp purge_bstate(bs, expiret) when is_map(bs) do
    Enum.map(bs,
      fn {hp, %{failts: fts}} -> {hp, %{failts: purge_fail_ts(fts, expiret)}} end) |>
      Enum.into(%{})
  end

  def fstate(hp) do
    GenServer.call(__MODULE__, {:fstate, hp})
  end

  def broker_probability(hp) do
    GenServer.call(__MODULE__, {:broker_probability, hp})
  end
  def clear_broker(hp) do
    GenServer.call __MODULE__, {:clear_broker, hp}
  end

  def fail_broker(hp) do
    GenServer.call __MODULE__, {:fail_broker, hp}
  end

  def handle_call({:fstate, hp}, _from, st) do
    {:reply,
      get_in_default(st, [:bstate, hp, :failts], []) |>
      Enum.count(),
      Map.put(st, :bstate, purge_bstate(st[:bstate], st[:purge_timeout]))
    }
  end

  def handle_call({:clear_broker, hp}, _from, st) do
    log(:info, "Clearing broker fail state for #{hp}")
    nst = purge_bstate(st[:bstate], st[:purge_timeout]) |>
      put_in([hp, :failts], [])
    {:reply, :ok, Map.put(st, :bstate, nst)}
  end

  def handle_call({:fail_broker, hp}, _from, st) do
    oldts = get_in_default(st, [:bstate, hp, :failts], [])
    nst = purge_bstate(st[:bstate], st[:purge_timeout]) |>
      put_in([hp, :failts],
        [(DateTime.utc_now() |> DateTime.to_unix()) | oldts])
    {:reply, :ok, Map.put(st, :bstate, nst)}
  end

  def handle_call({:broker_probability, hp}, _from, st) do
    {:reply,
      max(0, 10 - (get_in_default(st, [:bstate, hp, :failts], []) |>
                   Enum.count())),
      Map.put(st, :bstate, purge_bstate(st[:bstate], st[:purge_timeout]))}
  end
end

defmodule Remsign.FrontendPool do
  import Logger, only: [log: 2]
  use Honeydew

  defp make_sock(ident, h, p) when is_binary(ident) and is_binary(h) and is_integer(p) do
    case ExChumak.socket(:req, String.to_charlist(ident)) do
      {:ok, sock} -> case ExChumak.connect(sock, :tcp, String.to_charlist(h), p) do
                       {:ok, _spid} -> {h <> ":" <> to_string(p), sock}
                       e ->
                         log(:error, "Unable to connect to #{h}:#{p}: #{inspect(e)}")
                         nil
                     end
      e ->
        log(:error, "Unable to declare REQ socket #{ident}: #{inspect(e)}")
        nil
    end
  end

  defp hrand do
    :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
  end

  def init({brokers, keys, kid, skew, timeout, tries}) do
    socks = Enum.map(brokers,
      fn c = %{ "host" => h, "port" => p } ->
        log(:debug, "Make sock #{inspect(c)}"); make_sock(Map.get(c, "ident", "remsign-client") <> "." <> hrand, h, p) end) |>
      Enum.reject(fn x -> x == nil end) |>
      Enum.into(%{})
    {:ok, %{
            socks: socks, keys: keys, skew: skew,
            keyid: kid, timeout: timeout,
            tries: tries }}
  end

  defp totalized_list(l) when is_list(l) do
    List.foldl(l, {0, []},
      fn
        {_hp, 0}, {tot, l} -> {tot, l}
        {hp, bp},{tot, l} -> {tot+bp, l ++ [{hp, bp, tot+bp}]}
      end)
  end

  defp fetch_brokers(st) do
    Map.get(st, :socks, %{}) |>
    Map.keys |>
    Enum.map(fn hp -> {hp, Remsign.Frontend.broker_probability(hp)} end) |>
    Enum.sort(fn {_, bp1}, {_, bp2} -> bp1 > bp2 end) |>
    totalized_list
  end

  defp get_broker(tp, []), do: {nil, tp, []}

  defp get_broker(tp, bl) do
    # Pick a random member of the list, weighted by the probability
    # accompanying each element. The sum of all probabilities is given
    # as the first parameter.
    #
    # Return a tuple of 3 elements:
    #  1 - the randomly selected item from the original list
    #  2 - the new sum of probabilities (ie, the original sum minus
    #                                    that of the selected item)
    #  3 - the original list, with the selected item removed
    sel = :rand.uniform(tp)
    ndx = Enum.find_index(bl, fn {_hp, _bp, accp} -> sel <= accp end)
    {:ok, {hp, bp, _accp}} = Enum.fetch(bl, ndx)
    {hp, tp - bp, List.delete_at(bl, ndx) }
  end

  defp sign_helper(kf, keyid, htype, digest, st) do
    {tot_prob, bl} = fetch_brokers(st)
    log(:info, "tp = #{tot_prob}, broker list = #{inspect(bl)}")
    s = List.foldl(Enum.to_list(1..st[:tries]),
      {{tot_prob, bl}, []},
      fn _n, {{tp, rl}, l} -> {hp, ntp, nrl} = get_broker(tp, rl);
                              {{ntp, nrl}, l ++ [hp]} end) |>
      elem(1) |>
      Enum.reject(fn x -> x == nil end)

    # try each element in the broker list until
    # either we run out of brokers (in which case)
    # return the last error given, or we get a response
    # from a broker, in which case propagate that
    # result to the end
    Enum.reduce(s, {:error, :timeout},
      fn hp, {:error, _} ->
        log(:info, "Trying broker #{hp}")
        sock = st[:socks][hp]
        ret = find_key(st[:keys], st[:keyid]) |>
          handle_sign(hp, st[:keyid], kf, keyid, htype, digest,
                    st[:skew], sock, st[:timeout])
        case ret do
          {:error, e} -> {:error, e}
          %{"error" => e} -> {:error, e}
          m -> m
        end
          _hp, m -> m
      end)
  end

  def sign(keyid, htype, digest, st) do
    kf = fn kn, _public ->
      case find_key(st[:keys], kn) do
        nil -> nil
        k -> Map.get(k, "public")
      end
    end
    sign_helper(kf, keyid, htype, digest, st)
  end

  defp find_key(keys, keyid) do
    Enum.find(keys, fn %{ "name" => n } -> keyid == n end)
  end

  defp listen_worker(parent, sock, kf, skew, sm) do
    case ExChumak.send(sock, sm) do
      :ok -> case ExChumak.recv(sock) do
        {:ok, m} ->
          case Poison.decode(m) do
            {:ok, d} -> send parent, d
            {:error, _} ->
              r = Remsign.Utils.unwrap(m, kf, skew,
               fn n ->
                 Remsign.Utils.cc_store_nonce(:nonce_cache, n, skew * 2) end)
              send parent, Base.decode16(r, case: :mixed)
          end
        e ->
          log(:error, "Unwrap returns: #{inspect(e)}")
          send parent, {:error, :bad_reply}
        end
      e ->
        log(:error, "Unable to send to socket: #{inspect(e)}")
        send parent, {:error, :no_backend_available}
    end
  end

  defp handle_sign(nil, _, fe_keyid, _, _, _, _, _, _, _) do
    log(:error, "Unable to find front end key #{fe_keyid}")
    {:error, :missing_key}
  end

  defp handle_sign(k, hp, fe_keyid, kf, keyid, htype, digest, skew, sock, timeout) do
    msg = %{ payload: %{ command: :sign, parms: %{ keyname: keyid, hash_type: htype, digest: digest } } }
    km = Map.get(k, "private") |> JOSE.JWK.from_map
    sm = Remsign.Utils.wrap(msg, fe_keyid, "HS256", km)
    me = self
    spawn_link(fn -> listen_worker(me, sock, kf, skew, sm) end)
    receive do
      {:error, e} ->
        # Not a timeout - but could be a backend issue, so don't
        # alter the broker fail count one way or the other
        {:error, e}
      {:ok, m} ->
        log(:info, "Got response from broker #{hp}: #{inspect(m)}")
        Remsign.Frontend.clear_broker(hp)
        {:ok, m}
    after
      timeout ->
        Remsign.Frontend.fail_broker(hp)
        {:error, :timeout}
    end
  end
end
