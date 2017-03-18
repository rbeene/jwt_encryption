require IEx
defmodule JwtEncryption do
  import Plug.Conn
  @moduledoc """
  Documentation for JwtEncryption.
  """

  def init(options) do
    options
  end

  def call(conn, _options) do
    case conn |> get_req_header("authorization") do
      [authorization] ->
        auth = String.replace_prefix(authorization, "Bearer: ", "") |> decrypt
        conn |> put_req_header("authorization", "Bearer: #{auth}")
      _ ->
        conn
    end
  end

  @doc """
  Encrypts string values

  ## Examples

      iex> JwtEncryption.encrypt("Encryption for safety") |> JwtEncryption.decrypt
      "Encryption for safety"

  """
  def encrypt(val) do
    val
    |> :public_key.encrypt_private(private_key())
    |> Base.encode64
  end

  @doc """
  Decrypt strings

  ## Examples
    iex> JwtEncryption.decrypt("09ZpBkIxfeW1rqT2OYEdveArz/T1DNx+w/qhL4quSUvI5j8CLs4VlAw7kbMzHJT/NT2AtiHTwDPOkbLoRMWRt23bh31Nm3BkFCDW3F6MQgNAmZgXfwZUrfjWj8FGzq0IcfxOee5GEOSTcnX7Wp6b1l+JOsNO3QwegnOYR3lgm0USbZEBaJct9vAKayZKrw5/W5UabPO0fqcSDehFLIEzF799Oj57tCx7Kr5JeLAU0Nw7xrE2hQapeEjV3S+ro3uYBZgh6ai1dVeizUiH0Av/Di6cm/jfX3A6iyBT8Ez/T5hEeM97yn0IvyZ36LhyRhYvCDTF9MG+130GywZiT4rBjOCDKJt4smMKPZtLfWjIoeX8sRVSK/Aj06sANE6SNLz/qtjlBtU4eGpg32rS5wQdkzNb9DqiJyLZGVq0+QRnZ+ihzNyabbm+EjEZPhtfAxZG/gc+GOaO8rySbbuuB8BJXwvl284WtU6ps8NvDTAaKQsKmN3Si4TI+HNqFu7Rd9bhi1YWfM8Udh/s7AKTXriimWyYC9kPJiq7dRF+IjPP2dXzpwjnf9jNLAAvZK1P/rLKwwjNwoXPz2iDVmnEg84Qh5/alum3Kslt7anL8uT3zV6myTVbf4Q10t/mMq8ELvXeoTGXOFOZcjOWqb1A51uMfuX/FGO/GP1L4/7M4DUXlY4MpjNDnVQe4KsJrvcW0SdNPGWqo35Ka4Gp5dk9nOKQmZIMrBefleZuZT/2uQ9dCm6QDcPv+wzI7DUrNY6UX1Al9N7aK9s+9jhrIPNpJnUZ+H2am83IqL+VFyLU3KIqKQbOf0a7lnLVJuJEivxqwgowwA==")
    "Encryption for safety"

  """
  def decrypt(val) do
    with {:ok, value} <- val |> Base.decode64 do
      value |> :public_key.decrypt_public(public_key())
    else
      nil
    end
  end

  defp public_key() do
    {:ok, file} = Application.get_env(:jwt_encryption, :public_key)
    |> :file.read_file()

    :public_key.pem_decode(file)
    |> Enum.at(0)
    |> :public_key.pem_entry_decode
  end

  defp private_key() do
    IEx.pry
    {:ok, file} = Application.get_env(:jwt_encryption, :private_key)
    |> :file.read_file()

    :public_key.pem_decode(file)
    |> Enum.at(0)
    |> :public_key.pem_entry_decode(private_key_password())
  end

  defp private_key_password() do
    Application.get_env(:jwt_encryption, :private_key_password)
  end
end
