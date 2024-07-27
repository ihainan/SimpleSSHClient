package me.ihainan.packets
import java.io.File
import java.nio.ByteBuffer
import java.nio.file.Files
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.io.InputStream
import java.math.BigInteger
import java.security.spec.RSAPublicKeySpec
import me.ihainan.utils.SSHBuffer
import me.ihainan.utils.SSHStreamBufferReader
import me.ihainan.utils.SSHEncryptedStreamBufferReader

// https://www.rfc-editor.org/rfc/rfc4252#section-8
object AuthPacket {
  private val SSH_MSG_USERAUTH_REQUEST = 0x32.toByte
  private val SSH_MSG_USERAUTH_FAILURE = 0x33.toByte
  private val SSH_MSG_USERAUTH_SUCCESS = 0x34.toByte
  private val AUTH_SERVICE_NAME = "ssh-connection"

  def generatePasswordUserAuthPacket(username: String, password: String): SSHBuffer = {
    val buffer = new SSHBuffer()
    buffer.putByte(SSH_MSG_USERAUTH_REQUEST)
    buffer.putString(username)
    buffer.putString(AUTH_SERVICE_NAME)
    buffer.putString("password")
    buffer.putByte(0.toByte) // no need to change the password
    buffer.putString(password)
    buffer.encryptAndAppendMAC()
  }

  def readPasswordAuthenticationResponse(in: InputStream): Unit = {
    val reader = new SSHEncryptedStreamBufferReader(in)
    val payloadBuffer = reader.reader
    val paddingLength = payloadBuffer.getByte()
    val isSuccessful = payloadBuffer.getByte()
    if (isSuccessful == SSH_MSG_USERAUTH_FAILURE) {
      val nameList = payloadBuffer.getString()
      val partialSuccess = payloadBuffer.getByte()
      throw new Exception(
        s"Authentication failed, name list = {$nameList}, partialSuccess = $partialSuccess")
    } else {
      println("  Login succeeded")
    }
  }
}
