# This file is responsible for configuring your application
# and its dependencies with the aid of the Mix.Config module.
use Mix.Config

config :logger, [
  backends: [{LoggerFileBackend, :remsign_log}]
]

config :logger, :remsign_log,
  path: "/usr/local/remsign/var/log/remsign.log",
  level: :info,
  utc_log: true,
  format: "[$date $time] [$levelpad$level] ($node) $message\n"
