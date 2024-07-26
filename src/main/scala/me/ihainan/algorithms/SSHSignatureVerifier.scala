package me.ihainan.algorithms

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security._

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security._
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import me.ihainan.utils.SSHBuffer
import me.ihainan.algorithms
import me.ihainan.SSHSession._
import me.ihainan.utils.SSHFormatter
import java.security.spec.RSAPublicKeySpec
import me.ihainan.utils.SSHBufferReader
import me.ihainan.SSHSession

object SSHSignatureVerifier {
  // https://github.com/mwiede/jsch/blob/b32935200b0a102a545c2c62a6e1f38fcc78953e/src/main/java/com/jcraft/jsch/DHGN.java#L151
  // https://github.com/openssh/libopenssh/blob/05dfdd5f54d9a1bae5544141a7ee65baa3313ecd/ssh/kexdh.c#L40
  // https://github.com/apache/mina-sshd/blob/master/sshd-core/src/main/java/org/apache/sshd/server/kex/DHGServer.java#L47
  def verifySignature(signature: Array[Byte]): Boolean = {
    // V_C || V_S || I_C || I_S || K_S || e || f || K
    // NOTICE: Should put the length info into the buffer, E, F, K should be treated as MPInt
    val sha = MessageDigest.getInstance("SHA-256")
    val buffer = new SSHBuffer()
    buffer.putString(getClientVersion)
    buffer.putString(getServerVersion)
    buffer.putByteArrayWithLength(getIC())
    buffer.putByteArrayWithLength(getIS())
    buffer.putByteArrayWithLength(getKS())
    buffer.putMPInt(getE().toByteArray())
    buffer.putMPInt(getF())
    buffer.putMPInt(getK())
    sha.update(buffer.getData, 0, buffer.getData.length)

    // println("  getClientVersion = " + SSHFormatter.formatByteArray(getClientVersion.getBytes))
    // println("  getServerVersion = " + SSHFormatter.formatByteArray(getServerVersion.getBytes))
    // println("  getIC = " + SSHFormatter.formatByteArray(getIC()))
    // println("  getIS = " + SSHFormatter.formatByteArray(getIS()))
    // println("  getKS = " + SSHFormatter.formatByteArray(getKS()))
    // println("  getE = " + SSHFormatter.formatByteArray(getE().toByteArray))
    // println("  getF = " + SSHFormatter.formatByteArray(getF()))
    // println("  getK = " + SSHFormatter.formatByteArray(getK()))
    // println("  buffer = " + SSHFormatter.formatByteArray(buffer.getData))

    val H = sha.digest()
    SSHSession.setH(H)
    println("  H = " + SSHFormatter.formatByteArray(H))

    val sig = Signature.getInstance("SHA512withRSA")
    sig.initVerify(getServerRSAPublicKey());
    sig.update(H);
    val sigBuffer = new SSHBufferReader(signature)
    val sigName = sigBuffer.getString // rsa-sha2-512
    val sigLength = sigBuffer.getInt() // 256
    val finalSignature = sigBuffer.getByteArray(sigLength)
    val result = sig.verify(finalSignature)
    if (!result) {
      throw new Exception("Signature verification failed")
    }
    result
  }
}
