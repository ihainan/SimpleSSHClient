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

object AuthPacket {
  val SSH_MSG_USERAUTH_REQUEST = 0x32
  val AUTH_SERVICE_NAME = "ssh-connection"
  val AUTH_METHOD = "publickey"

  // def generateUserAuthRequest(): Unit = {
  //   val bytes = collection.mutable.ArrayBuffer.empty[Byte]

  //   // username
  //   val usernameLength = username.length()
  //   bytes.appendAll(SSHUtils.intToBytes(usernameLength))
  //   bytes.appendAll(username.getBytes())

  //   // service name
  //   bytes.appendAll(SSHUtils.intToBytes(AUTH_SERVICE_NAME.length()))
  //   bytes.appendAll(AUTH_SERVICE_NAME.getBytes())

  //   // auth method
  //   bytes.appendAll(SSHUtils.intToBytes(AUTH_METHOD.length()))
  //   bytes.appendAll(AUTH_METHOD.getBytes())

  //   // this is an auth request
  //   bytes += 0.toByte
  // }

  def buildAuthRequest(username: String, publicKeyPath: String): Array[Byte] = {
    // 读取公钥
    val publicKey = readPublicKey(publicKeyPath)

    // 构建认证请求
    val buffer = ByteBuffer.allocate(1024) // 分配足够大的缓冲区

    // SSH_MSG_USERAUTH_REQUEST (50)
    buffer.put(50.toByte)

    // 用户名
    putString(buffer, username)

    // 服务名 (通常是 "ssh-connection")
    putString(buffer, "ssh-connection")

    // 认证方法 ("publickey")
    putString(buffer, "publickey")

    // FALSE (表示这是一个认证请求，而不是实际的签名)
    buffer.put(0.toByte)

    // 公钥算法名称 ("ssh-rsa")
    putString(buffer, "ssh-rsa")

    // 公钥数据
    val encodedPublicKey = encodePublicKey(publicKey)
    putString(buffer, encodedPublicKey)

    // 获取最终的 byte 数组
    val result = new Array[Byte](buffer.position())
    buffer.flip()
    buffer.get(result)

    result
  }

  private def readPublicKey(publicKeyPath: String): RSAPublicKey = {
    val publicKeyContent = new String(Files.readAllBytes(new File(publicKeyPath).toPath)).trim
    val parts = publicKeyContent.split("\\s+")
    val keyData = if (parts.length >= 2) parts(1) else publicKeyContent
    val decoded = Base64.getDecoder.decode(keyData)
    val spec = new X509EncodedKeySpec(decoded)
    val kf = KeyFactory.getInstance("RSA")
    kf.generatePublic(spec).asInstanceOf[RSAPublicKey]
  }

  private def encodePublicKey(publicKey: RSAPublicKey): Array[Byte] = {
    val buffer = ByteBuffer.allocate(512)
    putString(buffer, "ssh-rsa")
    putMPInt(buffer, publicKey.getPublicExponent)
    putMPInt(buffer, publicKey.getModulus)
    val result = new Array[Byte](buffer.position())
    buffer.flip()
    buffer.get(result)
    result
  }

  private def putString(buffer: ByteBuffer, str: String): Unit = {
    val strBytes = str.getBytes
    buffer.putInt(strBytes.length)
    buffer.put(strBytes)
  }

  private def putString(buffer: ByteBuffer, data: Array[Byte]): Unit = {
    buffer.putInt(data.length)
    buffer.put(data)
  }

  private def putMPInt(buffer: ByteBuffer, bi: java.math.BigInteger): Unit = {
    val bytes = bi.toByteArray
    if ((bytes(0) & 0x80) != 0) {
      buffer.putInt(bytes.length + 1)
      buffer.put(0.toByte)
      buffer.put(bytes)
    } else {
      buffer.putInt(bytes.length)
      buffer.put(bytes)
    }
  }

}

object SSHChallengeReader {

  case class ServerChallenge(
      publicKeyAlgorithm: String,
      publicKey: RSAPublicKey
  )

  def readServerChallenge(inputStream: InputStream): ServerChallenge = {
    // 读取报文长度
    val lengthBuffer = new Array[Byte](4)
    inputStream.read(lengthBuffer)
    val messageLength = ByteBuffer.wrap(lengthBuffer).getInt

    // 读取整个报文
    val messageBuffer = new Array[Byte](messageLength)
    inputStream.read(messageBuffer)
    val buffer = ByteBuffer.wrap(messageBuffer)

    // 验证消息类型
    val messageType = buffer.get()
    if (messageType != 60) { // SSH_MSG_USERAUTH_PK_OK
      throw new IllegalStateException(s"Unexpected message type: $messageType")
    }

    // 读取公钥算法
    val publicKeyAlgorithm = readString(buffer)

    // 读取公钥数据
    val publicKeyData = readByteArray(buffer)
    val publicKeyBuffer = ByteBuffer.wrap(publicKeyData)

    // 解析公钥
    val keyType = readString(publicKeyBuffer)
    if (keyType != "ssh-rsa") {
      throw new IllegalStateException(s"Unsupported key type: $keyType")
    }

    val exponent = readMPInt(publicKeyBuffer)
    val modulus = readMPInt(publicKeyBuffer)

    // 创建 RSAPublicKey
    val keySpec = new RSAPublicKeySpec(modulus, exponent)
    val keyFactory = KeyFactory.getInstance("RSA")
    val publicKey = keyFactory.generatePublic(keySpec).asInstanceOf[RSAPublicKey]

    ServerChallenge(publicKeyAlgorithm, publicKey)
  }

  private def readString(buffer: ByteBuffer): String = {
    val length = buffer.getInt
    val bytes = new Array[Byte](length)
    buffer.get(bytes)
    new String(bytes, "UTF-8")
  }

  private def readByteArray(buffer: ByteBuffer): Array[Byte] = {
    val length = buffer.getInt
    val bytes = new Array[Byte](length)
    buffer.get(bytes)
    bytes
  }

  private def readMPInt(buffer: ByteBuffer): BigInteger = {
    val length = buffer.getInt
    val bytes = new Array[Byte](length)
    buffer.get(bytes)
    new BigInteger(1, bytes)
  }
}
