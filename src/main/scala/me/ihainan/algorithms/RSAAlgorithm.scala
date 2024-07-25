package me.ihainan.algorithms

import java.security.interfaces.RSAPublicKey
import java.nio.charset.StandardCharsets
import java.nio.ByteBuffer
import me.ihainan.utils.SSHBuffer
import me.ihainan.utils.SSHStreamBufferReader
import java.util.Base64
import java.math.BigInteger
import java.security.spec.RSAPublicKeySpec
import java.security.KeyFactory
import java.io.ByteArrayOutputStream

object RSAAlgorithm {
  def encodeRSAPublicKey(key: RSAPublicKey): String = {
    val sshRsa = "ssh-rsa".getBytes(StandardCharsets.UTF_8)
    val eBytes = key.getPublicExponent.toByteArray
    val nBytes = key.getModulus.toByteArray
    val totalLength = 4 + sshRsa.length + 4 + eBytes.length + 4 + nBytes.length
    val buffer = new SSHBuffer()
    buffer.putByteArray(sshRsa)
    buffer.putByteArray(eBytes)
    buffer.putByteArray(nBytes)
    val serverRSAPublicKeyStr = Base64.getEncoder().encodeToString(buffer.getData)
    serverRSAPublicKeyStr
  }

  import java.security.interfaces.RSAPublicKey
  import java.io.{ByteArrayOutputStream, DataOutputStream}
  import java.nio.charset.StandardCharsets
  import java.util.Base64

  private def sshString(str: String): Array[Byte] = {
    sshString(str.getBytes(StandardCharsets.UTF_8))
  }

  private def sshString(byteArray: Array[Byte]): Array[Byte] = {
    val byteStream = new ByteArrayOutputStream()
    val dataStream = new DataOutputStream(byteStream)
    dataStream.writeInt(byteArray.length)
    dataStream.write(byteArray)
    byteStream.toByteArray
  }

  def convertToOpenSSHFormat(publicKey: RSAPublicKey): String = {
    // 获取Modulus和Exponent的字节表示
    val modulusBytes = publicKey.getModulus.toByteArray
    val exponentBytes = publicKey.getPublicExponent.toByteArray

    // 构建SSH公钥头部
    val byteStream = new ByteArrayOutputStream()
    byteStream.write(sshString("ssh-rsa"))
    byteStream.write(sshString(exponentBytes))
    byteStream.write(sshString(modulusBytes))

    // 将所有字节编码为Base64
    val keyStr = Base64.getEncoder.encodeToString(byteStream.toByteArray)

    s"ssh-rsa $keyStr"
  }

  def generateRSAPublicKey(e: BigInteger, n: BigInteger): RSAPublicKey = {
    val spec = new RSAPublicKeySpec(n, e)
    val keyFactory = KeyFactory.getInstance("RSA")
    keyFactory.generatePublic(spec).asInstanceOf[RSAPublicKey]
  }
}
