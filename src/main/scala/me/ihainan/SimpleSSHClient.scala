package me.ihainan

import java.net.Socket
import java.io.InputStream
import java.io.OutputStream
import scala.util.Random

class SimpleSSHClient(
    val host: String,
    val port: Int,
    val username: String,
    val password: String
) {
  private val socket: Socket = createConnection()
  private val in: InputStream = socket.getInputStream
  private val out: OutputStream = socket.getOutputStream

  private val SSH_CLIENT_VERSON = "SSH-2.0-0penSSH_9.6"
  private var serverClientVersion: String = _

  private val clientAlrithms = AlgorithmNegotiationPacket.getClientAlgorithms()
  private var serverAlgorithms: AlgorithmNegotiationPacket = _

  def createConnection(): Socket = {
    val socket = new Socket(host, port)
    println("Server connected")
    socket
  }

  def connect(): Unit = {
    // Send client's SSH version to the server
    sendClientVersion()

    // Receive server's SSH version
    receiveServerVersion()

    // TODO: check the compatibility between the client and server

    // client key exchange init
    sendClientAlgorithms()

    // server key exchange init
    receiveServerAlgorithms()

    // sends public key to the server
    clientKEX()

    // receive server's public to generate shared secret
    serverKEX()

    // TODO: client sends the NEW KEYS packet to the server
    // TODO: client sends the encrypted data to the server
  }

  def sendClientVersion(): Unit = {
    println(s"Sending client version $SSH_CLIENT_VERSON to the server")
    val clientVersionBytes = SSH_CLIENT_VERSON.getBytes()
    out.write(clientVersionBytes)
    out.write(0x0d)
    out.write(0x0a)
    out.flush
    println("Version sent")
  }

  def receiveServerVersion(): Unit = {
    val buffer = collection.mutable.ArrayBuffer.empty[Byte]
    var lastByte: Int = -1
    var currentByte: Int = -1
    while (serverClientVersion == null && {
        currentByte = in.read; currentByte != -1
      }) {
      if (lastByte == 0x0d && currentByte == 0x0a) {
        buffer.trimEnd(1)
        serverClientVersion = new String(buffer.toArray)
        println(s"serverClientVersion = $serverClientVersion")
      }
      buffer += currentByte.toByte
      lastByte = currentByte
    }
  }

  private def sendClientAlgorithms(): Unit = {
    out.write(clientAlrithms.toFullBytes)
  }

  private def receiveServerAlgorithms(): Unit = {
    serverAlgorithms = AlgorithmNegotiationPacket.readAlgorithmsFromInputStream(in)

    println("Server algorithms: ")
    println(serverAlgorithms)
  }

  private def clientKEX(): Unit = {
    val clientKEXPacket = DiffieHellmanGroup14Packet.generateDHInitPacket()
    out.write(clientKEXPacket)
    out.flush()
    println("clientKEX sent")
  }

  private def serverKEX(): Unit = {
    // DiffieHellmanGroup14Packet.keyExchangeAlgorithm.testDH()
    DiffieHellmanGroup14Packet.parseServerPublicKey(in, SSH_CLIENT_VERSON, serverClientVersion)
  }

  def closeConnection(): Unit = {
    if (socket != null) {
      socket.close()
    }
  }
}

object SimpleSSHClient extends App {
  val client = new SimpleSSHClient("la.ihainan.me", 22, "user", "password")
  client.connect()
  client.closeConnection()
}
