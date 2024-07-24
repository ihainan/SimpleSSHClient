package me.ihainan.algorithms

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security._
import java.util.Base64
import javax.crypto.KeyAgreement
import java.math.BigInteger
import javax.crypto.spec.DHParameterSpec
import javax.crypto.interfaces.DHPublicKey
import org.bouncycastle.util.BigIntegers
import javax.crypto.spec.DHPublicKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.interfaces.RSAPublicKey
import java.nio.charset.StandardCharsets
import java.nio.ByteBuffer
import org.bouncycastle.util.encoders.{Base64 => BCBase64}
import javax.crypto.interfaces.DHPrivateKey

class KeyExchangeAlgorithm {
  Security.addProvider(new BouncyCastleProvider())

  // parameters
  // val MODP_GROUP_14 =
  //   "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
  //     "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
  //     "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
  //     "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
  //     "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
  //     "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
  //     "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
  //     "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
  val p: Array[Byte] = Array(
    0x00.toByte,
    0xff.toByte,
    0xff.toByte,
    0xff.toByte,
    0xff.toByte,
    0xff.toByte,
    0xff.toByte,
    0xff.toByte,
    0xff.toByte,
    0xc9.toByte,
    0x0f.toByte,
    0xda.toByte,
    0xa2.toByte,
    0x21.toByte,
    0x68.toByte,
    0xc2.toByte,
    0x34.toByte,
    0xc4.toByte,
    0xc6.toByte,
    0x62.toByte,
    0x8b.toByte,
    0x80.toByte,
    0xdc.toByte,
    0x1c.toByte,
    0xd1.toByte,
    0x29.toByte,
    0x02.toByte,
    0x4e.toByte,
    0x08.toByte,
    0x8a.toByte,
    0x67.toByte,
    0xcc.toByte,
    0x74.toByte,
    0x02.toByte,
    0x0b.toByte,
    0xbe.toByte,
    0xa6.toByte,
    0x3b.toByte,
    0x13.toByte,
    0x9b.toByte,
    0x22.toByte,
    0x51.toByte,
    0x4a.toByte,
    0x08.toByte,
    0x79.toByte,
    0x8e.toByte,
    0x34.toByte,
    0x04.toByte,
    0xdd.toByte,
    0xef.toByte,
    0x95.toByte,
    0x19.toByte,
    0xb3.toByte,
    0xcd.toByte,
    0x3a.toByte,
    0x43.toByte,
    0x1b.toByte,
    0x30.toByte,
    0x2b.toByte,
    0x0a.toByte,
    0x6d.toByte,
    0xf2.toByte,
    0x5f.toByte,
    0x14.toByte,
    0x37.toByte,
    0x4f.toByte,
    0xe1.toByte,
    0x35.toByte,
    0x6d.toByte,
    0x6d.toByte,
    0x51.toByte,
    0xc2.toByte,
    0x45.toByte,
    0xe4.toByte,
    0x85.toByte,
    0xb5.toByte,
    0x76.toByte,
    0x62.toByte,
    0x5e.toByte,
    0x7e.toByte,
    0xc6.toByte,
    0xf4.toByte,
    0x4c.toByte,
    0x42.toByte,
    0xe9.toByte,
    0xa6.toByte,
    0x37.toByte,
    0xed.toByte,
    0x6b.toByte,
    0x0b.toByte,
    0xff.toByte,
    0x5c.toByte,
    0xb6.toByte,
    0xf4.toByte,
    0x06.toByte,
    0xb7.toByte,
    0xed.toByte,
    0xee.toByte,
    0x38.toByte,
    0x6b.toByte,
    0xfb.toByte,
    0x5a.toByte,
    0x89.toByte,
    0x9f.toByte,
    0xa5.toByte,
    0xae.toByte,
    0x9f.toByte,
    0x24.toByte,
    0x11.toByte,
    0x7c.toByte,
    0x4b.toByte,
    0x1f.toByte,
    0xe6.toByte,
    0x49.toByte,
    0x28.toByte,
    0x66.toByte,
    0x51.toByte,
    0xec.toByte,
    0xe4.toByte,
    0x5b.toByte,
    0x3d.toByte,
    0xc2.toByte,
    0x00.toByte,
    0x7c.toByte,
    0xb8.toByte,
    0xa1.toByte,
    0x63.toByte,
    0xbf.toByte,
    0x05.toByte,
    0x98.toByte,
    0xda.toByte,
    0x48.toByte,
    0x36.toByte,
    0x1c.toByte,
    0x55.toByte,
    0xd3.toByte,
    0x9a.toByte,
    0x69.toByte,
    0x16.toByte,
    0x3f.toByte,
    0xa8.toByte,
    0xfd.toByte,
    0x24.toByte,
    0xcf.toByte,
    0x5f.toByte,
    0x83.toByte,
    0x65.toByte,
    0x5d.toByte,
    0x23.toByte,
    0xdc.toByte,
    0xa3.toByte,
    0xad.toByte,
    0x96.toByte,
    0x1c.toByte,
    0x62.toByte,
    0xf3.toByte,
    0x56.toByte,
    0x20.toByte,
    0x85.toByte,
    0x52.toByte,
    0xbb.toByte,
    0x9e.toByte,
    0xd5.toByte,
    0x29.toByte,
    0x07.toByte,
    0x70.toByte,
    0x96.toByte,
    0x96.toByte,
    0x6d.toByte,
    0x67.toByte,
    0x0c.toByte,
    0x35.toByte,
    0x4e.toByte,
    0x4a.toByte,
    0xbc.toByte,
    0x98.toByte,
    0x04.toByte,
    0xf1.toByte,
    0x74.toByte,
    0x6c.toByte,
    0x08.toByte,
    0xca.toByte,
    0x18.toByte,
    0x21.toByte,
    0x7c.toByte,
    0x32.toByte,
    0x90.toByte,
    0x5e.toByte,
    0x46.toByte,
    0x2e.toByte,
    0x36.toByte,
    0xce.toByte,
    0x3b.toByte,
    0xe3.toByte,
    0x9e.toByte,
    0x77.toByte,
    0x2c.toByte,
    0x18.toByte,
    0x0e.toByte,
    0x86.toByte,
    0x03.toByte,
    0x9b.toByte,
    0x27.toByte,
    0x83.toByte,
    0xa2.toByte,
    0xec.toByte,
    0x07.toByte,
    0xa2.toByte,
    0x8f.toByte,
    0xb5.toByte,
    0xc5.toByte,
    0x5d.toByte,
    0xf0.toByte,
    0x6f.toByte,
    0x4c.toByte,
    0x52.toByte,
    0xc9.toByte,
    0xde.toByte,
    0x2b.toByte,
    0xcb.toByte,
    0xf6.toByte,
    0x95.toByte,
    0x58.toByte,
    0x17.toByte,
    0x18.toByte,
    0x39.toByte,
    0x95.toByte,
    0x49.toByte,
    0x7c.toByte,
    0xea.toByte,
    0x95.toByte,
    0x6a.toByte,
    0xe5.toByte,
    0x15.toByte,
    0xd2.toByte,
    0x26.toByte,
    0x18.toByte,
    0x98.toByte,
    0xfa.toByte,
    0x05.toByte,
    0x10.toByte,
    0x15.toByte,
    0x72.toByte,
    0x8e.toByte,
    0x5a.toByte,
    0x8a.toByte,
    0xac.toByte,
    0xaa.toByte,
    0x68.toByte,
    0xff.toByte,
    0xff.toByte,
    0xff.toByte,
    0xff.toByte,
    0xff.toByte,
    0xff.toByte,
    0xff.toByte,
    0xff.toByte
  )
  // private val P = new BigInteger(MODP_GROUP_14, 16)
  private val P = new BigInteger(1, p)
  private val G = BigInteger.valueOf(2)
  private val keyPairGenerator = KeyPairGenerator.getInstance("DH", "BC")
  private val dhSpec = new DHParameterSpec(P, G)
  keyPairGenerator.initialize(dhSpec)

  // client's
  private val clientKeyPair = keyPairGenerator.generateKeyPair()
  private val clientPrivateKey = clientKeyPair.getPrivate
  private val clientPublicKey = clientKeyPair.getPublic.asInstanceOf[DHPublicKey]

  // server's
  private var serverDHPublicKey: DHPublicKey = _
  private var serverRSAPublicKey: RSAPublicKey = _

  // shared
  private var sharedSecret: Array[Byte] = _

  // for signature validation
  private var e: Array[Byte] = _ // client's DH public key
  private var f: Array[Byte] = _ // server's DH public key

  def testDH(): Unit = {
    val keyPair = keyPairGenerator.generateKeyPair()
    val serverPrivateKey = keyPair.getPrivate.asInstanceOf[DHPrivateKey]
    val serverDHPublicKey = keyPair.getPublic.asInstanceOf[DHPublicKey]
    val keyAgreement = KeyAgreement.getInstance("DH", "BC")
    keyAgreement.init(clientPrivateKey)
    keyAgreement.doPhase(serverDHPublicKey, true)
    keyAgreement.generateSecret()

    // Convert server public key to bytes and back as a test
    val serverDHPublicKeySpec = serverDHPublicKey.asInstanceOf[DHPublicKey]
    val serverPublicKeyBytes = serverDHPublicKeySpec.getY.toByteArray

    val f = new BigInteger(1, serverPublicKeyBytes)
    val dhPublicKeySpec = new DHPublicKeySpec(f, P, G)
    val keyFactory = KeyFactory.getInstance("DH", "BC")
    keyFactory.generatePublic(dhPublicKeySpec).asInstanceOf[DHPublicKey]

    keyAgreement.init(clientPrivateKey)
    keyAgreement.doPhase(serverDHPublicKey, true)
  }

  def getClientPublicKeyBytes(): Array[Byte] = {
    // https://github.com/mwiede/jsch/blob/master/src/main/java/com/jcraft/jsch/jce/DH.java#L57
    clientPublicKey.getY.toByteArray()
  }

  private def printRSAPublicKey(key: RSAPublicKey): Unit = {
    val sshRsa = "ssh-rsa".getBytes(StandardCharsets.UTF_8)
    val eBytes = key.getPublicExponent.toByteArray
    val nBytes = key.getModulus.toByteArray
    val totalLength = 4 + sshRsa.length + 4 + eBytes.length + 4 + nBytes.length
    val buffer = ByteBuffer.allocate(totalLength)
    buffer.putInt(sshRsa.length)
    buffer.put(sshRsa)
    buffer.putInt(eBytes.length)
    buffer.put(eBytes)
    buffer.putInt(nBytes.length)
    buffer.put(nBytes)

    val serverRSAPublicKeyStr = Base64.getEncoder().encodeToString(buffer.array())
    println(s"serverRSAPublicKeyStr = $serverRSAPublicKeyStr")
  }

  def setserverRSAPublicKey(e: BigInteger, n: BigInteger): Unit = {
    val spec = new RSAPublicKeySpec(n, e)
    val keyFactory = KeyFactory.getInstance("RSA")
    serverRSAPublicKey = keyFactory.generatePublic(spec).asInstanceOf[RSAPublicKey]
    printRSAPublicKey(serverRSAPublicKey)
  }

  def setServerDHPublicKey(dhServerF: Array[Byte]): Unit = {
    val f = new BigInteger(1, dhServerF);
    val dhPublicKeySpec = new DHPublicKeySpec(f, P, G);
    val keyFactory = KeyFactory.getInstance("DH");
    serverDHPublicKey = keyFactory.generatePublic(dhPublicKeySpec).asInstanceOf[DHPublicKey];
    println("serverDHPublicKey = " + new String(BCBase64.encode(serverDHPublicKey.getEncoded())))
  }

  def generateSharedSecret(): Unit = {
    val keyAgreement = KeyAgreement.getInstance("DH", "BC")
    keyAgreement.init(clientPrivateKey)
    keyAgreement.doPhase(serverDHPublicKey, true)
    sharedSecret = keyAgreement.generateSecret()
    println("sharedSecret = " + new String(BCBase64.encode(sharedSecret)))
  }

  private def bytesToBigInteger(bytes: Array[Byte]): BigInteger = {
    // 前4个字节是长度
    val length = ((bytes(0) & 0xff) << 24) |
      ((bytes(1) & 0xff) << 16) |
      ((bytes(2) & 0xff) << 8) |
      (bytes(3) & 0xff)

    // 从第5个字节开始是实际的整数数据
    new BigInteger(1, bytes.slice(4, 4 + length))
  }

  def validateSignature(clientVersion: String,
                        serverVersion: String,
                        clientKexInit: Array[Byte],
                        serverKexInit: Array[Byte],
                        signature: Array[Byte]): Unit = {
    val e = bytesToBigInteger(clientPublicKey.getEncoded())
    val f = bytesToBigInteger(serverDHPublicKey.getEncoded())
    val k = new BigInteger(sharedSecret)
    SSHSignatureVerifier.verifySignature(
      clientVersion,
      serverVersion,
      clientKexInit,
      serverKexInit,
      serverRSAPublicKey,
      e,
      f,
      k,
      signature
    )
  }
}
