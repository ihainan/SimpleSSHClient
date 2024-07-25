package me.ihainan

import me.ihainan.algorithms.KeyExchangeAlgorithm
import java.lang
import java.io.InputStream
import java.nio.ByteBuffer

object DiffieHellmanGroup14Packet {
  private val DHKeyExchangeCode = 0x1e.toByte
  val keyExchangeAlgorithm = new KeyExchangeAlgorithm()

  private def generateDHInitPayload(): Array[Byte] = {
    // FORMAT:
    //  DHKeyExchangeCode(1 byte) + Public key length (4 bytes) + Public key
    val bytes = collection.mutable.ArrayBuffer.empty[Byte]

    // message code
    bytes += DHKeyExchangeCode

    // public key
    val clientPublicKey = keyExchangeAlgorithm.getClientPublicKeyBytes()
    bytes.appendAll(SSHUtils.intToBytes(clientPublicKey.length))
    bytes.appendAll(clientPublicKey)

    // return
    bytes.toArray
  }

  def generateDHInitPacket(): Array[Byte] = {
    // FORMAT:
    //  Packet length (4 bytes) + Padding length (1 byte) + Payload + Padding
    val bytes = collection.mutable.ArrayBuffer.empty[Byte]
    val payloadBytes = generateDHInitPayload()
    val payloadLength = payloadBytes.length
    val paddingLength = SSHUtils.calculatePaddingLength(payloadLength)
    val packetLength = payloadLength + paddingLength + 1
    val paddings = (0 until paddingLength).map(_ => 0.toByte)
    // println(
    //   s"payloadLength = $payloadLength, paddingLength = $paddingLength, packetLength = $packetLength")

    // packet length + padding length
    bytes.appendAll(SSHUtils.intToBytes(packetLength))
    bytes += paddingLength.toByte

    // payload + paddings
    bytes.appendAll(payloadBytes)
    bytes.appendAll(paddings)

    // return
    bytes.toArray
  }

  def parseServerPublicKey(
    in: InputStream, 
    clientVersion: String, 
    serverVersion: String,
    ic: Array[Byte],
    is: Array[Byte]): Unit = {
    val packetLength = SSHUtils.readInt(in)
    val paddingLength = in.read()
    val serverKexPayload = SSHUtils.readByteArray(in, packetLength - 1)

    // parse the payload
    val messageCode = serverKexPayload(0)
    if (messageCode != 0x1f) {
      throw new Exception(s"Invalid message code: $messageCode")
    }

    // read kex host key info to get the RSA public key
    val hostKeyLength = ByteBuffer.wrap(serverKexPayload.slice(1, 5)).getInt
    val kexHostInfo = new KexHostKeyReader(serverKexPayload.slice(5, 5 + hostKeyLength)).read()
    keyExchangeAlgorithm.setserverRSAPublicKey(kexHostInfo.e, kexHostInfo.n)

    // read server's DH public key
    val serverFAndSignBytes = serverKexPayload.slice(5 + hostKeyLength, serverKexPayload.length)
    val serverPubKeyLength = ByteBuffer.wrap(serverFAndSignBytes.slice(0, 4)).getInt
    val serverPublicKeyBytes = serverFAndSignBytes.slice(4, 4 + serverPubKeyLength)
    keyExchangeAlgorithm.setFBytes(serverPublicKeyBytes)
    keyExchangeAlgorithm.setServerDHPublicKey(serverPublicKeyBytes)

    // read signature
    val signBytes = serverFAndSignBytes.slice(4 + serverPubKeyLength, serverFAndSignBytes.length)
    val signLength = ByteBuffer.wrap(signBytes.slice(0, 4)).getInt
    val sign = signBytes.slice(4, 4 + signLength)

    // generate the shared key
    keyExchangeAlgorithm.generateSharedSecret()

    // validate the signature
    // keyExchangeAlgorithm.verifySignature(clientVersion, serverVersion, ic, is, sign)
  }
}
