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

  def generateRSAPublicKey(e: BigInteger, n: BigInteger): RSAPublicKey = {
    val spec = new RSAPublicKeySpec(n, e)
    val keyFactory = KeyFactory.getInstance("RSA")
    keyFactory.generatePublic(spec).asInstanceOf[RSAPublicKey]
  }
}
