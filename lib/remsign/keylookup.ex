defmodule Remsign.Keylookup do
  @moduledoc """
  Lookup for public/private keys for use via JWT/JOSE
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
      {:error, _} ->
        nil
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
    pass = Map.get(c, "pass")
    priv = Map.get(c, "private")
    pk = read_private_key_h(priv, pass)
    case pk do
      nil -> c
      p ->
        Map.delete(c, "pass") |> Map.put("private", p)
    end
  end

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
      nil -> c
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
