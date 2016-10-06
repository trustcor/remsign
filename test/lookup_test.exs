defmodule RemsignLookupTest do
  use ExUnit.Case

  setup_all do
    {:ok, td} = Briefly.create(directory: true)
    Enum.each(["d1", "d1/d1", "d1/d2", "d2", "d3", "d3/d1", "d3/d2"],
      fn d -> File.mkdir_p!(Path.join(td, d)) end)
    content = [
      { "d1/f1.txt", "Test file 1" },
      { "d1/f1.yml", """
      ---
      name: Key 1
      algs:
        - rs256
        - rs384
        - ps256
        - ps384
      private: privkey.pem
      pass: file:privkey.pass
      public: pubkey.pem
      """},
      { "d1/privkey.pem", """
        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: AES-128-CBC,4004915908F73CEE7CB6FA4F6CF236E6

        fPYC35/6isg1TfDnYwKb0jMwI6aMtU3zoDs/M4ZcHMjBXA3+Ta6nR4iq9r8CXa2P
        iei0r+/UXTVohDjNujtx8UK7dtoLbDfL+HJgSyTyn24+gsWUTG4cXrGm0+P0RLsT
        vcqm5jg5Cx3cYjQojp0OmXSwL1JhoZxMh4/L9o8aGx0yfyocRjSpax8/QwjtR/SL
        wj8YcIG1xeQt2AYjHb5NzIaxz6InIEPYE42TbxaHXR4=
        -----END RSA PRIVATE KEY-----
        """},
      { "d1/pubkey.pem", """
        -----BEGIN PUBLIC KEY-----
        MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAJ0BGMWITUY8KkOR0E7D7kgjSM+HlBqo
        2K3xD9RcqtE5AgMBAAE=
        -----END PUBLIC KEY-----
        """},
      { "d1/privkey.pass", "secretpass\n" }, # should strip the trailing whitespace
      { "d1/d1/f1.txt", "Test file 2" },
      { "d1/d2/f1.txt", "Test file 3" },
      { "d1/d2/f2.txt", "Test file 4" },
      { "d3/f1.txt", "Test file 5" },
      { "d3/d2/f1.txt", "Test file 6" },
      { "d3/d2/osshpriv.pem", """
         -----BEGIN OPENSSH PRIVATE KEY-----
         b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
         QyNTUxOQAAACCgadrDh1Aopi4o0Wzyth+GZWTDr8UqNeTijuSYEerawQAAAJB+nYuffp2L
         nwAAAAtzc2gtZWQyNTUxOQAAACCgadrDh1Aopi4o0Wzyth+GZWTDr8UqNeTijuSYEerawQ
         AAAEBc429RjbkX0xR3BWt5bvTWID4XIGJTMhgqYNzUBZIZPaBp2sOHUCimLijRbPK2H4Zl
         ZMOvxSo15OKO5JgR6trBAAAAB2Zvb0BiYXIBAgMEBQY=
         -----END OPENSSH PRIVATE KEY-----
         """},
      { "d3/d2/ossh.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKBp2sOHUCimLijRbPK2H4ZlZMOvxSo15OKO5JgR6trB foo@bar" },
      { "d3/d2/ossh.yml", """
         ---
         name: Key 2
         algs:
           - ed25519
         private: osshpriv.pem
         public: ossh.pub
         """ }
    ]
    Enum.each(content, fn {fname, c} -> File.write!(Path.join(td, fname), c) end)
    on_exit fn -> File.rm_rf(td) end
    [
      td: td,
      txt_files: Enum.filter(content, fn {fname, _} -> String.ends_with?(fname, ".txt") end) |> Enum.map(&(elem(&1,0))),
      yml_files: Enum.filter(content, fn {fname, _} -> String.ends_with?(fname, ".yml") end) |> Enum.map(&(elem(&1,0)))
    ]

  end

  test "get listing", ctx do
    assert Remsign.Keylookup.find_control_files(ctx[:td], fn x -> x end, [".txt"]) |> Enum.sort ==
      Enum.map(ctx[:txt_files], fn f -> Path.join(ctx[:td], f) end) |> Enum.sort
  end

  test "get yaml listing", ctx do
    assert Remsign.Keylookup.find_control_files(ctx[:td], fn x -> x end) |> Enum.sort ==
      Enum.map(ctx[:yml_files], fn f -> Path.join(ctx[:td], f) end) |> Enum.sort
  end

  test "get yaml private key read", ctx do
    assert Remsign.Keylookup.find_control_files(ctx[:td], fn x -> Remsign.Keylookup.read_yaml_file(x) end) |>
      Enum.sort(fn %{"name" => a}, %{ "name" => b} -> a < b end) ==
      [
        %{
          "name" => "Key 1",
          "algs" => ["rs256", "rs384", "ps256", "ps384"],
          "private" => {
            %{kty: :jose_jwk_kty_rsa},
            %{
              "kty" => "RSA",
              "d" => "iFPNeKfTwWq4oBdasyn6Ghkq-dXSjEAzs6tmg1VTJmk",
              "dp" => "Edo937xbhiI_piYx122_Zw",
              "dq" => "srWR6h0j5Rh6vjz2rIKe1w",
              "e" => "AQAB",
              "n" => "nQEYxYhNRjwqQ5HQTsPuSCNIz4eUGqjYrfEP1Fyq0Tk",
              "p" => "ynUGKA5R4pNqSg9TqbBMww",
              "q" => "xobGNiRu5_mB9CKLkY96Uw",
              "qi" => "WNjuNLi0IPts3V6IBfuXvg"}},
          "public" => %{
            "e" => "AQAB",
            "kty" => "RSA",
            "n" => "nQEYxYhNRjwqQ5HQTsPuSCNIz4eUGqjYrfEP1Fyq0Tk="
          }
        },
        %{
          "name" => "Key 2",
          "algs" => ["ed25519"],
          "private" => {
            %{kty: :jose_jwk_kty_okp_ed25519},
            %{
              "kid" => "foo@bar",
              "crv" => "Ed25519",
              "d" => "XONvUY25F9MUdwVreW701iA-FyBiUzIYKmDc1AWSGT0",
              "kty" => "OKP",
              "x" => "oGnaw4dQKKYuKNFs8rYfhmVkw6_FKjXk4o7kmBHq2sE"
            }
          },
          "public" => %{
            "crv" => "Ed25519",
            "kty" => "OKP",
            "x" => "oGnaw4dQKKYuKNFs8rYfhmVkw6_FKjXk4o7kmBHq2sE"
          }
        }
      ]
  end
end
