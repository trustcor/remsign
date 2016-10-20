defmodule Remsign.Keylookup do
  @moduledoc """
  Lookup for public/private keys for use via JWT/JOSE.
  """
  import Logger, only: [log: 2]


  defp find_control_files_h(dir, f, extensions) do
    case File.ls(dir) do
      {:ok, flist} ->
        Enum.map(flist,
          fn fname -> case File.dir?(Path.join(dir, fname)) do
                        true ->
                          find_control_files_h(Path.join(dir, fname), f, extensions)
                        false ->
                          case Enum.any?(extensions, fn e -> String.ends_with?(fname, e) end) do
                            true -> f.(Path.join(dir, fname))
                            false -> nil
                          end
                      end
          end)
      {:error, e} ->
        log(:error, "Unable to search directory #{dir}: #{inspect(e)}")
        []
    end
  end

  def find_control_files(dir, f), do: find_control_files(dir, f, [".yml"])

  def find_control_files(dir, f, extensions), do: List.flatten(find_control_files_h(dir, f, extensions)) |> Enum.reject(&(&1 == nil))

  defp absjoin(l) when is_list(l), do: Path.absname(Path.join(l))

  defp interpolate_path(dir, p) do
    case Path.type(p) do
      :absolute -> p
      :relative -> absjoin([dir, p])
      :volumerelative -> absjoin([dir, p])
    end
  end
  defp interpolate_item(dir, "private", v) do
    interpolate_path(dir, v)
  end
  defp interpolate_item(dir, "public", v) do
    interpolate_path(dir, v)
  end
  defp interpolate_item(dir, "pass", v) do
    case String.split(v, ":", parts: 2) do
      ["file", path] ->
        case Path.type(path) do
          :absolute ->
            v
          :relative ->
            "file:" <> absjoin([dir, path])
          :volumerelative ->
            "file:" <> absjoin([dir, path])  # not testing on Windows, so may not work
        end
      _ ->
        v
    end
  end

  defp interpolate_item(_dir, _k, v), do: v

  defp interpolate_paths(c = %{}, fpath) do
    dir = Path.dirname(fpath)
    Enum.map(c, fn {k, v} -> {k, interpolate_item(dir, k, v)} end) |>
      Enum.into(%{})
  end

  defp interpolate_paths(c, fpath) do
    log(:error, "YAML Content from #{fpath} is not a map")
    c
  end

  defp read_private_key_h(pfile, pass) do
    case File.read(pfile) do
      {:ok, content} ->
        pkp = privkey_password(pass)

        case :public_key.pem_decode(content) do
          [key] ->
            try do
              :public_key.pem_entry_decode(key, pkp) |> JOSE.JWK.from_key |> JOSE.JWK.to_map
            rescue
              MatchError ->
                log(:error, "Unable to decode private key in #{pfile}. Wrong passphrase?")
              nil
            end
          [] ->
            JOSE.JWK.from_openssh_key(content) |> JOSE.JWK.to_map
        end
      {:error, e} ->
        log(:error, "Unable to open private key file #{pfile}: #{inspect(e)}")
        nil
    end
  end

  defp _privkey_password(["env", var]) do
    case System.get_env(var) do
      nil -> nil
      e -> String.trim_trailing(e)
    end
  end

  defp _privkey_password(["pass", var]) do
    String.trim_trailing(var)
  end

  defp _privkey_password(["file", var]) do
    case File.read(var) do
      {:ok, cont} ->
        case String.printable?(cont) do
          true -> String.trim_trailing(cont)
          _ -> cont
        end
      {:error, e} ->
        log(:error, "Unable to open passphrase file #{inspect(var)}: #{inspect(e)}")
        nil
    end
  end

  defp _privkey_password([s1, s2]), do: s1 <> ":" <> s2

  defp privkey_password(s) when is_binary(s) do
    String.split(s, ":", parts: 2) |> _privkey_password() |> :binary.bin_to_list
  end

  defp privkey_password(nil), do: nil

  defp read_private_key(c = %{}) do
    pk = case Map.get(c, "oct") do
           nil -> read_private_key_h(Map.get(c, "private"), Map.get(c, "pass"))
           s when is_binary(s) ->
             case Base.url_decode64(s, padding: false) do
               {:ok, b} ->
                 {_, t} = JOSE.JWK.from_oct(b) |> JOSE.JWK.to_map
                 t
               :error ->
                 log(:error, "Invalid URLsafe base64 for oct field")
                 nil
             end
         end
    case pk do
      nil -> c
      p ->
        Map.delete(c, "pass") |> Map.delete("oct") |> Map.put("private", p)
    end
  end

  defp read_public_key_h(nil), do: nil

  defp read_public_key_h(pfile) do
    case File.read(pfile) do
      {:ok, content} ->
        Remsign.Pubkey.load_key(content)
      {:error, e} ->
        log(:error, "Unable to open private key file #{pfile}: #{inspect(e)}")
        nil
    end
  end

  defp read_public_key(c = %{}) do
    case read_public_key_h(Map.get(c, "public")) do
      nil -> case Map.get(c, "private") do
               pk = %{ "kty" => "oct" } -> Map.put(c, "public", pk)
               _ -> c # anything else, just pass through
             end
      p -> Map.put(c, "public", p)
    end
  end

  defp read_keys(c = %{}) do
    read_private_key(c) |> read_public_key
  end

  def read_yaml_file(fpath) do
    case File.read(fpath) do
      {:ok, content} ->
        content |>
          YamlElixir.read_from_string |>
          interpolate_paths(fpath) |>
          read_keys
      {:error, e} ->
        log(:error, "Unable to read YAML file #{fpath}: #{inspect(e)}")
        %{}
    end
  end
end

defmodule Remsign.Lookup do
  @callback lookup(keyname :: String.t, keytype :: atom()) :: map() | nil
  @callback lookup(keyname :: String.t, keytype :: String.t) :: map() | nil
  @callback listkeys() :: map()
end

defmodule Remsign.FileKeyLookup do
  import Logger, only: [log: 2]
  use GenServer
  @behaviour Remsign.Lookup

  def init([dir, extensions]) do
    case File.dir?(dir) do
      true ->
        keys = Remsign.Keylookup.find_control_files(dir, &Remsign.Keylookup.read_yaml_file/1, extensions)
        log(:info, "keys = #{inspect(keys)}")
        {:ok, %{directory: dir, extensions: extensions, keys: keys}}
      _ -> {:stop, :no_directory}
    end
  end

  def start_link(dir), do: start_link(dir, [ ".yml" ])

  def start_link(dir, extensions) do
    GenServer.start_link __MODULE__, [dir, extensions], name: __MODULE__
  end

  def lookup(keyname, keytype) when is_atom(keytype), do: lookup(keyname, to_string(keytype))

  def lookup(keyname, keytype) when is_binary(keyname) and is_binary(keytype) do
    GenServer.call __MODULE__, {:lookup, keyname, keytype}
  end

  def listkeys() do
    GenServer.call __MODULE__, :list_keys
  end

  def handle_call({:lookup, keyname, keytype}, _from, st) when is_binary(keyname) and is_binary(keytype) do
    {:reply,
     case Enum.find(st[:keys], fn %{ "name" => n } -> keyname == n end) do
       nil -> nil
       k -> Map.get(k, keytype)
     end,
     st}
  end

  def handle_call(:list_keys, _from, st) do
    {:reply,
     Enum.map(st[:keys], fn k = %{ "name" => n, "private" => _pk } -> {n, Map.get(k, "public")} end) |>
       Enum.reject(fn {_n, k} -> k == nil or Map.get(k, "kty") == "oct" end) |>
       Enum.into(%{}),
     st}
  end

end
