package me.ihainan.packets

import java.lang
import java.io.InputStream
import java.nio.ByteBuffer
import me.ihainan.utils.SSHBuffer
import me.ihainan.utils.SSHStreamBufferReader
import me.ihainan.utils.SSHBufferReader
import com.ibm.j9ddr.vm29.pointer.generated.messagePointer
import java.math.BigInteger
import me.ihainan.SSHSession
import me.ihainan.algorithms.RSAAlgorithm

object DiffieHellmanGroup14Packet {
  private val DH_EXCHANGE_CODE = 0x1e.toByte

  private def generatePayload(): SSHBuffer = {
    val buffer = new SSHBuffer()
    buffer.putByte(DH_EXCHANGE_CODE)
    val clientE = SSHSession.keyExchangeAlgorithm.clientE
    buffer.putMPInt(clientE)
    buffer
  }

  def generateDHInitPacket(): SSHBuffer = {
    val payloadBuffer = generatePayload()
    val buffer = payloadBuffer.wrapWithPadding()
    buffer
  }

  def readServerPublibKeyFromInputStream(in: InputStream): Unit = {
    // parse packet
    val streamReader = new SSHStreamBufferReader(in)
    val reader = streamReader.reader
    val packetLength = streamReader.packetLength
    val paddingLength = reader.getByte()
    val payloadBytes = reader.getByteArray(packetLength - paddingLength - 1)
    val payloadReader = new SSHBufferReader(payloadBytes)

    // read payload
    val messageCode = payloadReader.getByte()
    println(s"  packet message code = $messageCode")
    val hostKeyLength = payloadReader.getInt()
    val hostKeyReader = new SSHBufferReader(payloadReader.getByteArray(hostKeyLength))
    val hostKeyType = hostKeyReader.getString()
    val serverRSAE = new BigInteger(hostKeyReader.getMPInt())
    val serverRSAN = new BigInteger(hostKeyReader.getMPInt())
    val serverDHF = payloadReader.getMPInt()
    val signatureBytes = payloadReader.getByteArray()

    // Generate server's public key
    val serverRSAPublicKey = RSAAlgorithm.generateRSAPublicKey(serverRSAE, serverRSAN)

    // TODO: validate server's public key
    println("  " + RSAAlgorithm.encodeRSAPublicKey(serverRSAPublicKey))

    // Save into SSHSession
    SSHSession.setF(new BigInteger(serverDHF))

    // validate the signature
    // keyExchangeAlgorithm.verifySignature(clientVersion, serverVersion, ic, is, sign)
  }
}
