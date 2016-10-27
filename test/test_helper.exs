defmodule TestUtils do
  def test_key_lookup("key1", :private) do
    {%{kty: :jose_jwk_kty_rsa},
     %{"kty" => "RSA",
       "d" => "fzunouHbBg5Ney9099vfoPKQcEdQVVWAIBp-E3tdT2CaXDEq8U0PXrhLVkcX3Snzurk11wBKlqREwFnYetQf6G95jdkmTqck5Zbtp1uBfuLKqHVChsxMWEj3GHij5Aziz_rD-x5GCUdXj7hWx3pb3wsdvpb92n4cpNZQeqd7NaNNVCCQzllP9t_fN5Zw_MRR1wA68SvhCT4iWf3bw3LRMMMk7nBLH0b4GZcjf_eHMqx2e4SwGe-S8QOd8Uuyx_5Rw6WaVUb2s4TdZaqGXwwcsUXEl7RXFYeQj0XlQfY-fapaOLDn0js5entfpzuAawLHMgjFirmKNLWDARDG6_4B",
       "dp" => "LF5GzJ6Rj_4_sXbN9umVOfbtlX3uPyb9p62czxlD98i1Fu993-ARoGU73xhgZoRdB4nEI6RzV6hEH8vP8lB7e-FMp38QBE8GK7QGtyTE0zloCjF6-qcLPBCcxrwmuVT9vHmCzHBJuhRnfLHwqbCLVgQUtZrS0bJxh9gQ-aoFAIE",
       "dq" => "mLX3qHyeMB1gSQmC-9nh4HddLyGDSRpmZJgbEiLF5MbLieE55IFR6utOyXkT7sBqjoYRTQKPWRWqF1X1sKTR4Sxi4yuRB-CPLhu08mMMX1czGIk_KV8Uwl_zPnhAb8F56N-D14e-ag6ZoYTpuI0aucXhV9Gu32SaMfyCMG54iEc",
       "e" => "AQAB",
       "n" => "tv1Xitb_3VsTeBKbi_W0ef1mquuCUXiR60us17GIVHuPcVK8mR-k64x2A7L0srTy5xV8ft2r_ncqRey5SOE6lmDo-UYLuq6r78v5KK5AggBpxWSOXCDTnwqDbH4uiw9_zXgzt-w7MEFDXZKNqXHRCqVgDfWNlNTN2_i_vFv87Xs9JgFK9STa69Hp7Z0nOXAwuitVnXZeW2DvZjB0Q3E7zGZK2wLSeepQWo-pvcPAJBKVlET3KuyQUPBprfrA5_pG4ziQ76K6nqp5TFfQR2jfDiRDO0-RVp-hQvqbcMx9WBzcQuk_md7BjM2W5nYT-uJTvFag82sLvmxoZJsNNyDN2w",
       "p" => "5iK19qrD0L9CWXvDk09TSNeR3mWqUTD81SH85OmNTW6AfTnSUYejdNK4v4OBTgAxhC4G4Hcde3GE2pOJZMR9I_Beg6bCiPyV6C1FnvBBpWWN6-Qk9YaC_aBYAFfNDYyIbY6k7MtN1KTLsAmr_VmYb6r1UOS3fuvdcLRsEVK9aYE",
       "q" => "y44ut59bHdvAstRsw_yCk5jKQ4ZSD75Zyk-GrHemsQsWOH9FwNviDVNCb9m_h3nhjkxhzHaB4rZN_eg7OYLaeZba9k1c5ABOuBLNRWvnP8kc3rm5Fl0-ORR8jtQrTKCQV9sJLK1KY0GZIDI1uxZ78ic5FyOPejnARcN89ihQzVs",
       "qi" => "kPJdSD3gwV5RurP84aCKAwNxf6kycvSMF5q1f5Ji-ahxcLyKvg1yRp7a-mzbK421E_84dfN47wK3Bs-wI80KjpZA_HZ1UkiZGzoaJ7FawqjnsxSS6f7ugdeUGersL7OUDe0HoJEN_qmdFdkX2tSqTK8gGS0jsDZ-2d_r1XnZSR8"
     }
    }
  end

  def test_key_lookup("key1", :public) do
    %{
      "kty" => "RSA",
      "e" => "AQAB",
      "n" => "tv1Xitb_3VsTeBKbi_W0ef1mquuCUXiR60us17GIVHuPcVK8mR-k64x2A7L0srTy5xV8ft2r_ncqRey5SOE6lmDo-UYLuq6r78v5KK5AggBpxWSOXCDTnwqDbH4uiw9_zXgzt-w7MEFDXZKNqXHRCqVgDfWNlNTN2_i_vFv87Xs9JgFK9STa69Hp7Z0nOXAwuitVnXZeW2DvZjB0Q3E7zGZK2wLSeepQWo-pvcPAJBKVlET3KuyQUPBprfrA5_pG4ziQ76K6nqp5TFfQR2jfDiRDO0-RVp-hQvqbcMx9WBzcQuk_md7BjM2W5nYT-uJTvFag82sLvmxoZJsNNyDN2w"
    }
  end

  def test_key_lookup("key2", :private) do
    %{
      "kty" => "EC",
      "crv" => "P-256",
      "d" => "BwaAjOTXQ8Ad67nX3dZtOtjAqa2U5auP_cVVusuH-Qk",
      "x" => "UFxInAzw5bTawwntTBYL6iTC-GpToXkx2F9zGjRbKps",
      "y" => "3uwsTiV1FFY5mJ_GqkXrPq0enOFubkiQ1Ts7OK2BGIM"
    }
  end

  def test_key_lookup("key2", :public) do
    %{
      "kty" => "EC",
      "crv" => "P-256",
      "x" => "UFxInAzw5bTawwntTBYL6iTC-GpToXkx2F9zGjRbKps",
      "y" => "3uwsTiV1FFY5mJ_GqkXrPq0enOFubkiQ1Ts7OK2BGIM"
    }
  end

  def test_key_lookup("key3", :private) do
    %{
      "crv" => "Ed25519",
      "d" => "Ml05uJSjmIavqINFAJ1i3yJ65T0uyqjVwB7X1ehn4sg",
      "kty" => "OKP",
      "x" => "PgH0Bdgk0y6eVC7GrmJO2bnFick1nzSCcTPHAR4xcO0"
    }
  end

  def test_key_lookup("key3", :public) do
    %{
      "crv" => "Ed25519",
      "kty" => "OKP",
      "x" => "PgH0Bdgk0y6eVC7GrmJO2bnFick1nzSCcTPHAR4xcO0"
    }
  end

  def test_key_lookup("test-dealer", :private) do
    %{
      "crv" => "Ed25519",
      "d" => "Ml05uJSjmIavqINFAJ1i3yJ65T0uyqjVwB7X1ehn4sg",
      "kty" => "OKP",
      "x" => "PgH0Bdgk0y6eVC7GrmJO2bnFick1nzSCcTPHAR4xcO0"
    }
  end

  def test_key_lookup("test-dealer", :public) do
    %{
      "crv" => "Ed25519",
      "kty" => "OKP",
      "x" => "PgH0Bdgk0y6eVC7GrmJO2bnFick1nzSCcTPHAR4xcO0"
    }
  end

  def test_key_lookup("test-backend", :private) do
    %{
      "crv" => "Ed25519",
      "d" => "XONvUY25F9MUdwVreW701iA-FyBiUzIYKmDc1AWSGT0",
      "kty" => "OKP",
      "x" => "oGnaw4dQKKYuKNFs8rYfhmVkw6_FKjXk4o7kmBHq2sE"
    }
  end

  def test_key_lookup("test-backend", :public) do
    %{
      "crv" => "Ed25519",
      "kty" => "OKP",
      "x" => "oGnaw4dQKKYuKNFs8rYfhmVkw6_FKjXk4o7kmBHq2sE"
    }
  end

  def test_key_lookup("fe-key", _) do
    %{
      "k" => "488vgbyX9wFaDLoZvx4ePfSYU3bYaoCeTxl-_nOYNX8",
      "kty" => "oct"
    }
  end

  def test_key_lookup(n, "private"), do: test_key_lookup(n, :private)
  def test_key_lookup(n, "public"), do: test_key_lookup(n, :public)

  def test_key_lookup(_, _), do: nil

  def test_public_keys() do
    kns = [ "fe-key", "test-backend", "test-dealer", "key1", "key2", "key3" ]
    Enum.map(kns, fn kn -> { kn, test_key_lookup(kn, :public) } end) |>
      Enum.reject(fn {_n, k} -> k == nil or Map.get(k, "kty") == "oct" end) |>
      Enum.into(%{})
  end
end

defmodule TestKeyLookup do
  use GenServer

  def init([]) do
    {:ok, %{}}
  end

  def start_link() do
    GenServer.start_link __MODULE__, [], name: __MODULE__
  end

  def handle_call({:lookup, kn, kt}, _from, st) when is_binary(kt) do
    rep = TestUtils.test_key_lookup(kn, kt)
    {:reply, rep, st}
  end

  def handle_call({:lookup, kn, kt}, _from, st) when is_atom(kt) do
    rep = TestUtils.test_key_lookup(kn, kt)
    {:reply, rep, st}
  end

  def handle_call(:list_keys, _from, st) do
    {:reply, TestUtils.test_public_keys(), st}
  end

  def handle_call(:backend, _from, st) do
    {:reply, st[:backend], st}
  end

  def handle_call({:set_backend, be}, _from, st) do
    {:reply, :ok, Map.put(st, :backend, be)}
  end

  def backend(), do: GenServer.call __MODULE__, :backend
  def set_backend(be), do: GenServer.call __MODULE__, {:set_backend, be}

end

ExUnit.start()
