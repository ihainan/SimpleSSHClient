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
import me.ihainan.SSHUtils

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
  val p: Array[Byte] = Array(0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda,
    0xa2, 0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e,
    0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08,
    0x79, 0x8e, 0x34, 0x04, 0xdd, 0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a,
    0x6d, 0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5,
    0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c,
    0xb6, 0xf4, 0x06, 0xb7, 0xed, 0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24,
    0x11, 0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d, 0xc2, 0x00, 0x7c,
    0xb8, 0xa1, 0x63, 0xbf, 0x05, 0x98, 0xda, 0x48, 0x36, 0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f,
    0xa8, 0xfd, 0x24, 0xcf, 0x5f, 0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3,
    0x56, 0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d, 0x67, 0x0c, 0x35,
    0x4e, 0x4a, 0xbc, 0x98, 0x04, 0xf1, 0x74, 0x6c, 0x08, 0xca, 0x18, 0x21, 0x7c, 0x32, 0x90, 0x5e,
    0x46, 0x2e, 0x36, 0xce, 0x3b, 0xe3, 0x9e, 0x77, 0x2c, 0x18, 0x0e, 0x86, 0x03, 0x9b, 0x27, 0x83,
    0xa2, 0xec, 0x07, 0xa2, 0x8f, 0xb5, 0xc5, 0x5d, 0xf0, 0x6f, 0x4c, 0x52, 0xc9, 0xde, 0x2b, 0xcb,
    0xf6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7c, 0xea, 0x95, 0x6a, 0xe5, 0x15, 0xd2, 0x26,
    0x18, 0x98, 0xfa, 0x05, 0x10, 0x15, 0x72, 0x8e, 0x5a, 0x8a, 0xac, 0xaa, 0x68, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff).map(_.toByte)
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
  private var eBytesFromSSHMessage: Array[Byte] = _ // client's DH public key
  private var fBytesFromSSHMessage: Array[Byte] = _ // server's DH public key

  def setFBytes(bytes: Array[Byte]): Unit = {
    fBytesFromSSHMessage = bytes
  }

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
    eBytesFromSSHMessage = clientPublicKey.getY.toByteArray()
    eBytesFromSSHMessage
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
    println(s"  serverRSAPublicKeyStr = $serverRSAPublicKeyStr")
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
  
  def verifySignature(clientVersion: String,
                        serverVersion: String,
                        clientKexInit: Array[Byte],
                        serverKexInit: Array[Byte],
                        signature: Array[Byte]): Unit = {
    println("Verifying signature...")
    println(s"  clientVersion = $clientVersion")
    println(s"  serverVersion = $serverVersion")
    println(s"  clientKexInit = ${SSHUtils.formatByteArray(clientKexInit)}")
    println(s"  serverKexInit = ${SSHUtils.formatByteArray(serverKexInit)}")
    println(s"  eBytesFromSSHMessage = ${SSHUtils.formatByteArray(eBytesFromSSHMessage)}")
    println(s"  fBytesFromSSHMessage = ${SSHUtils.formatByteArray(fBytesFromSSHMessage)}")
    val e = bytesToBigInteger(eBytesFromSSHMessage)
    val f = bytesToBigInteger(fBytesFromSSHMessage)
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
