defmodule Remsign.Mixfile do
  use Mix.Project

  def project do
    [app: :remsign,
     version: "0.1.0",
     elixir: "~> 1.3",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     elixirc_paths: elixirc_paths(Mix.env),
     deps: deps()]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    [applications: [:logger, :chumak, :poison, :timex,
                    :briefly, :yamerl, :yaml_elixir, :con_cache,
                    :edeliver
                   ],
     included_applications: [:exactor, :joken, :jose,
                             :libdecaf, :libsodium ]
    ]
  end

  defp deps do
    [
      {:edeliver, "~> 1.4.0"},
      {:distillery, "~> 0.10.1"},
      {:chumak, "~> 1.1"},
      {:jose, "~> 1.8.0"},
      {:libsodium, "~> 0.0.8"},
      {:libdecaf, "~> 0.0.4"},
      {:poison, "~> 2.0.0"},
      {:joken, "~> 1.3.1"},
      {:timex, "~> 3.0.0"},
      {:briefly, "~> 0.3.0"},
      {:yaml_elixir, "~> 1.0.0"},
      {:yamerl, github: "yakaz/yamerl"},
      {:con_cache, "~> 0.11.1" }
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/test_helpers"]
  defp elixirc_paths(_), do: ["lib"]
end
