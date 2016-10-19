defmodule Remsign.Frontend do
  @moduledoc """
  GenServer implementation which connects to multiple brokers and
  issues and processes signing requests to them.
  """

  import Logger, only: [log: 2]
  import Remsign.Utils, only: [get_in_default: 3]

  use GenServer

  defp make_sock(ident, h, p) when is_binary(ident) and is_binary(h) and is_integer(p) do
    case :chumak.socket(:req, String.to_charlist(ident)) do
      {:ok, sock} -> case :chumak.connect(sock, :tcp, String.to_charlist(h), p) do
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

  def init([cfg]) do
    socks = Enum.map(get_in_default(cfg, [:frontend, :brokers], []),
      fn c = %{ "host" => h, "port" => p } ->
        log(:debug, "Make sock #{inspect(c)}"); make_sock(Map.get(c, "ident", "remsign-client"), h, p) end) |>
      Enum.reject(fn x -> x == nil end) |>
      Enum.into(%{})
    keys = Remsign.Keylookup.find_control_files( get_in(cfg, [:keys, :directory]),
      fn x -> Remsign.Keylookup.read_yaml_file(x) end )
    log(:debug, "Socks = #{inspect(socks)}")
    {:ok, %{ socks: socks,
             keys: keys,
             keyid: get_in_default(cfg, [:frontend, :keyid], "remsign-client-key"),
             skew: get_in_default(cfg, [:frontend, :skew], 30) }}
  end

  def start_link(cfg) do
    GenServer.start_link __MODULE__, [cfg], name: __MODULE__
  end

  defp sign_h(_, nil, _), do: {:error, :unknown_digest_type}
  defp sign_h(keyid, htype, digest) when is_binary(keyid) and is_atom(htype) and is_binary(digest) do
    GenServer.call(__MODULE__, {:sign, keyid, htype, digest})
  end

  defp sign_m(keyid, htype, message) do
    d = :crypto.hash(htype, message) |> Base.encode16(case: :lower)
    sign_h(keyid, htype, d)
  end

  def dsign(keyid, hash_type, digest), do:  sign_h(keyid, Remsign.Utils.known_hash(hash_type), digest)
  def sign(keyid, hash_type, message), do: sign_m(keyid, Remsign.Utils.known_hash(hash_type), message)

  defp find_key(keys, keyid) do
    Enum.find(keys, fn %{ "name" => n } -> keyid == n end)
  end

  defp handle_sign(nil, fe_keyid, _, _, _, _, _, _) do
    log(:error, "Unable to find front end key #{fe_keyid}")
    {:error, :missing_key}
  end

  defp handle_sign(k, fe_keyid, kf, keyid, htype, digest, skew, sock) do
    msg = %{ payload: %{ command: :sign, parms: %{ keyname: keyid, hash_type: htype, digest: digest } } }
    km = Map.get(k, "private") |> JOSE.JWK.from_map
    sm = Remsign.Utils.wrap(msg, fe_keyid, "HS256", km)
    case :chumak.send(sock, sm) do
      :ok -> case :chumak.recv(sock) do
               {:ok, m} ->
                 case Poison.decode(m) do
                   {:ok, d} -> d
                   {:error, _} ->
                     r = Remsign.Utils.unwrap(m, kf, skew, fn n -> Remsign.Utils.cc_store_nonce(:nonce_cache, n, skew * 2) end)
                     Base.decode16(r, case: :mixed)
                 end
               e ->
                 log(:error, "Unwrap returns: #{inspect(e)}")
                 {:error, :bad_reply}
             end
      e ->
        log(:error, "Unable to send to socket: #{inspect(e)}")
        {:error, :no_backend_available}
    end
  end

  def handle_call({:sign, keyid, htype, digest}, _from, st) do
    s = Map.get(st, :socks, %{}) |> Map.keys |> Enum.shuffle
    sock = st[:socks][List.first(s)]
    kf = fn kn, _public ->
      case find_key(st[:keys], kn) do
        nil -> nil
        k -> Map.get(k, "public")
      end
    end
    rep = find_key(st[:keys], st[:keyid]) |>
      handle_sign(st[:keyid], kf, keyid, htype, digest, st[:skew], sock)

    {:reply, rep, st}
  end

end
