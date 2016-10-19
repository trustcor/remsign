defmodule Remsign.Config do
  import Logger, only: [log: 2]
  import Remsign.FileReader, only: [readinclude: 1]

  def atomify(cfg = %{}) do
    Enum.map(cfg, fn
      {k, v} when is_binary(k) and is_map(v) -> {String.to_atom(k), atomify(v)}
      {k, v} when is_binary(k) -> {String.to_atom(k), v}
      {k, v} when is_map(v) -> {String.to_atom(k), atomify(v)}
      {k, v} -> { k, v } end) |>
      Enum.into(%{})
  end

  def config(cfg) when is_map(cfg), do: atomify(cfg)

  def config(e) do
    log(:error, "Invalid config (must be a map): #{inspect(e)}")
    %{}
  end

  def config_yaml(ystr) when is_binary(ystr), do: YamlElixir.read_from_string(ystr) |> config

  def config_yaml_file(fname) do
    case readinclude(fname) do
      {:ok, cont} -> config_yaml(cont)
      e ->
        log(:error, "Unable to read config file #{inspect(fname)}: #{inspect(e)}")
        %{}
    end
  end
end
