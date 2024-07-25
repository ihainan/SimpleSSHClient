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

object SSHSignatureVerifier {
  // https://github.com/mwiede/jsch/blob/b32935200b0a102a545c2c62a6e1f38fcc78953e/src/main/java/com/jcraft/jsch/DHGN.java#L151
  def verifySignature(signature: Array[Byte]): Boolean = {
    // V_C || V_S || I_C || I_S || K_S || e || f || K
    val sha = MessageDigest.getInstance("SHA-256")
    val buffer = new SSHBuffer()
    // buffer.putString(getClientVersion)
    // buffer.putString(getServerVersion)
    // buffer.putString(new String(getIC()))
    // buffer.putString(new String(getIS()))
    // buffer.putString(new String(getKS()))
    // buffer.putMPInt(getE())
    // buffer.putMPInt(getF())
    // val bufferData = buffer.getData
    // md.update(bufferData, 0, bufferData.length)
    // md.update(getK(), 0, getK().length)

    buffer.putString(getClientVersion)
    buffer.putString(getServerVersion)
    buffer.putByteArrayWithLength(getIC())
    buffer.putByteArrayWithLength(getIS())
    buffer.putByteArrayWithLength(getKS())
    buffer.putMPInt(getE().toByteArray())
    buffer.putMPInt(getF())
    sha.update(buffer.getData, 0, buffer.getData.length)
    sha.update(getK(), 0, getK().length)

    // md.update(getClientVersion.getBytes())
    // md.update(getServerVersion.getBytes())
    // md.update(getIC())
    // md.update(getIS())
    // md.update(getKS())
    // md.update(getE().toByteArray())
    // md.update(getF())
    // md.update(getK())
    val H = sha.digest()
    println(SSHFormatter.formatByteArray(H))

    // val keyFactory = KeyFactory.getInstance("RSA");
    val sig = Signature.getInstance("SHA512withRSA")
    val e = Array(1.toByte, 0.toByte, 1.toByte)
    val n = Array(0x0.toByte, 0xd6.toByte, 0xa8.toByte, 0x0e.toByte, 0x1d.toByte, 0xf3.toByte, 0x0e.toByte, 0x2e.toByte, 0x6c.toByte, 0x56.toByte, 0x41.toByte, 0x1c.toByte, 0x53.toByte, 0x31.toByte, 0xf5.toByte, 0x5d.toByte, 0x61.toByte, 0xb0.toByte, 0x35.toByte, 0x21.toByte, 0xcc.toByte, 0xeb.toByte, 0x75.toByte, 0x87.toByte, 0xb2.toByte, 0xc0.toByte, 0x1e.toByte, 0x2e.toByte, 0x18.toByte, 0xdc.toByte, 0x79.toByte, 0x2b.toByte, 0xdc.toByte, 0x63.toByte, 0x32.toByte, 0x6a.toByte, 0x89.toByte, 0xf0.toByte, 0xd5.toByte, 0x8d.toByte, 0xea.toByte, 0xeb.toByte, 0x2e.toByte, 0x0f.toByte, 0x97.toByte, 0x9f.toByte, 0x7f.toByte, 0x05.toByte, 0x13.toByte, 0x11.toByte, 0x26.toByte, 0x09.toByte, 0x52.toByte, 0xde.toByte, 0x66.toByte, 0xf6.toByte, 0x01.toByte, 0xed.toByte, 0xd6.toByte, 0x46.toByte, 0x8c.toByte, 0xf7.toByte, 0xaa.toByte, 0x86.toByte, 0xe4.toByte, 0x4e.toByte, 0xf6.toByte, 0x38.toByte, 0x69.toByte, 0x13.toByte, 0xbc.toByte, 0x6c.toByte, 0xa6.toByte, 0xfd.toByte, 0xdb.toByte, 0xd7.toByte, 0x78.toByte, 0x78.toByte, 0x18.toByte, 0x7f.toByte, 0x83.toByte, 0x42.toByte, 0x80.toByte, 0x46.toByte, 0x67.toByte, 0x50.toByte, 0x1e.toByte, 0xea.toByte, 0xc1.toByte, 0x1b.toByte, 0x8e.toByte, 0xf8.toByte, 0xd9.toByte, 0xb5.toByte, 0xd9.toByte, 0x84.toByte, 0xfa.toByte, 0xf0.toByte, 0xb4.toByte, 0x7f.toByte, 0xa5.toByte, 0x75.toByte, 0x9e.toByte, 0x80.toByte, 0x39.toByte, 0xf0.toByte, 0x0d.toByte, 0xf7.toByte, 0x2c.toByte, 0x77.toByte, 0xbc.toByte, 0x7e.toByte, 0xc1.toByte, 0x35.toByte, 0x90.toByte, 0x90.toByte, 0x1d.toByte, 0x86.toByte, 0x56.toByte, 0x78.toByte, 0xb1.toByte, 0xb8.toByte, 0x34.toByte, 0xad.toByte, 0x42.toByte, 0x49.toByte, 0x4b.toByte, 0x13.toByte, 0x63.toByte, 0x23.toByte, 0xc1.toByte, 0x76.toByte, 0x01.toByte, 0x1c.toByte, 0x0e.toByte, 0xb0.toByte, 0x7c.toByte, 0x69.toByte, 0xb9.toByte, 0xdb.toByte, 0x51.toByte, 0xf0.toByte, 0xf1.toByte, 0x03.toByte, 0xb9.toByte, 0xb2.toByte, 0xec.toByte, 0x56.toByte, 0xc2.toByte, 0x04.toByte, 0x36.toByte, 0x98.toByte, 0xa0.toByte, 0xd6.toByte, 0x7d.toByte, 0xab.toByte, 0xdc.toByte, 0x6f.toByte, 0xbd.toByte, 0xc1.toByte, 0x4d.toByte, 0xc9.toByte, 0x0e.toByte, 0x88.toByte, 0x95.toByte, 0x99.toByte, 0xa7.toByte, 0x19.toByte, 0xc1.toByte, 0x4d.toByte, 0x78.toByte, 0x15.toByte, 0x31.toByte, 0xaa.toByte, 0x63.toByte, 0xc1.toByte, 0x67.toByte, 0x86.toByte, 0xe1.toByte, 0xcb.toByte, 0x59.toByte, 0xfd.toByte, 0x35.toByte, 0x2f.toByte, 0x15.toByte, 0xed.toByte, 0x76.toByte, 0xc2.toByte, 0x48.toByte, 0xfc.toByte, 0x81.toByte, 0xd9.toByte, 0xc2.toByte, 0xe4.toByte, 0x97.toByte, 0x01.toByte, 0x8b.toByte, 0x5b.toByte, 0x69.toByte, 0xc2.toByte, 0xa2.toByte, 0xcd.toByte, 0x4a.toByte, 0xae.toByte, 0xcf.toByte, 0xfc.toByte, 0x4a.toByte, 0x61.toByte, 0xa8.toByte, 0x9d.toByte, 0x4d.toByte, 0x7c.toByte, 0x80.toByte, 0xcc.toByte, 0x1e.toByte, 0xca.toByte, 0x6b.toByte, 0x61.toByte, 0x12.toByte, 0x15.toByte, 0xf9.toByte, 0x73.toByte, 0xab.toByte, 0xd8.toByte, 0xfe.toByte, 0xf4.toByte, 0xf9.toByte, 0xdd.toByte, 0xb8.toByte, 0xfd.toByte, 0x3d.toByte, 0x5f.toByte, 0xda.toByte, 0x41.toByte, 0x8e.toByte, 0x9c.toByte, 0x22.toByte, 0x03.toByte, 0xdc.toByte, 0x09.toByte, 0x17.toByte, 0x86.toByte, 0x58.toByte, 0x20.toByte, 0x95.toByte, 0xc8.toByte, 0x1a.toByte, 0xb8.toByte, 0x95.toByte, 0x92.toByte, 0x19.toByte, 0x82.toByte, 0x7c.toByte, 0xbf.toByte, 0x7b.toByte, 0xe5.toByte, 0xdd.toByte)
    val rsaPubKeySpec = new java.security.spec.RSAPublicKeySpec(new BigInteger(n), new BigInteger(e));
    val keyFactory = KeyFactory.getInstance("RSA");
    val pubKey = keyFactory.generatePublic(rsaPubKeySpec);
    sig.initVerify(pubKey);

    // sig.initVerify(getServerRSAPublicKey());
    sig.update(H);
    val sigBuffer = new SSHBufferReader(signature)
    val sigName = sigBuffer.getString // rsa-sha2-512
    val sigLength = sigBuffer.getInt() // 256
    val finalSignature = sigBuffer.getByteArray(sigLength)
    println(SSHFormatter.formatByteArray(finalSignature))
    val result = sig.verify(finalSignature)
    println(result)
    result
  }
}
