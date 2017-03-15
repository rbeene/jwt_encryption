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
    |> :public_key.encrypt_public(public_key())
    |> Base.encode64
  end

  @doc """
  Decrypt strings

  ## Examples
    iex> JwtEncryption.decrypt("G1G3holoRETC6r7EAergQbUY1ITKdwrRQyhihqlOLvDy4IW041V3iQgnDz8tu7+BOJgxDmUbaisY/hV6bECCYZDh2skTevPsqKp3EhwPv3OxNaSZFDsfTQnd+8GZ4C4F8Zz1llVWVQR+5MB1MhY5Kiv5IUq3/48Krh0crXgFf5Aov65AkndGcUNieHby+lFKMzLmnIeGYMI9du6VTnc837mhFA2XCLlS/oFn3OJ8qPPQg1gW2a9k010xcSf6H2+C23kVisLW0j7P9cDRNeZffO+v0dDfZRLmNYtgWN5ojZZ0XSldgZtNzv2ViIZieFASUc2F2jJGbpKrfR757TjvKHc8b7ZogL2QU9846rpHpUGmchnpmoripKoITjZAH3cfVStGOoYlO7aAM12ihL9VT3rpRg8Bam1p8a20444AikUz/om23/Cq4C1aOvMu8KfanH58p32cmRFu7vCx4Cp+QtjQiF7+aoWzqngBNiPcJTF4WuOOsDw79p0jEGX6AK6UNJG84HgV89MS1xu5nQViZpgL6ayb3eAdWQY5aMPUK2k5ORVFBAU4Z7avtsdnModyYi7U1Wt4+psxpYSnClCUQFVe12WJtPuyyBs5zci7Bml+w+ZP9LnPiRI1JfW2NnmmFtwAX8RPXipRui+Isot8pAV7JDZuMcaWsecRm0HcY8U/nCoq8Fuhw4r0H6uqJy6I+9ATCOq1X8Ga1rvAuxWdCOkh74dUk0bo5QpIVKBtQTmB2p0fCunUiKGVexriH3XK349+8r0pjIIc/CFEy6637ykE0KiV3zymqznfpdtinVr9HjiBNFu+GDL4Cbx5lNsIFQ==")
    "Encryption for safety"

  """
  def decrypt(val) do
    {:ok, val} = val |> Base.decode64

    val
    |> :public_key.decrypt_private(private_key())
  end

  defp public_key() do
    {:ok, file} = Application.get_env(:jwt_encryption, :public_key)
    |> :file.read_file()

    :public_key.pem_decode(file)
    |> Enum.at(0)
    |> :public_key.pem_entry_decode
  end

  defp private_key() do
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
