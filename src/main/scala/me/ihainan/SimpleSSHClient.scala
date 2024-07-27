package me.ihainan

import java.net.Socket
import java.io.InputStream
import java.io.OutputStream
import scala.util.Random
import me.ihainan.utils.SSHBuffer
import me.ihainan.packets._
import me.ihainan.utils.SSHFormatter

class SimpleSSHClient(
    val host: String,
    val port: Int,
    val username: String,
    val password: String
) {
  private val socket: Socket = createConnection()
  private val in: InputStream = socket.getInputStream
  private val out: OutputStream = socket.getOutputStream

  private val SSH_CLIENT_VERSON = "SSH-2.0-JSCH_0.2.18"

  private val clientAlrithms = AlgorithmNegotiationPacket.getClientAlgorithms()
  private var serverAlgorithms: AlgorithmNegotiationPacket = _

  def write(bytes: Array[Byte]): Unit = {
    out.write(bytes)
    out.flush()
  }

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

    // client sends/receives the NEW KEYS packet to/from the server
    sendNewKey()
    receiveNewKey()

    // read extra info from the server (optional)
    receiveExtInfo()

    // auth using password
    // sendAuthRequest()
  }

  def sendClientVersion(): Unit = {
    println(s"Sending SSH version to the server...")
    println(s"  clientSSHVersion = $SSH_CLIENT_VERSON")
    val buffer = new SSHBuffer()
    buffer.putByteArray(SSH_CLIENT_VERSON.getBytes())
    buffer.putByteArray(Array(0x0d, 0x0a)) // CR LF
    write(buffer.getData)
    SSHSession.setClientVersion(SSH_CLIENT_VERSON)
  }

  def receiveServerVersion(): Unit = {
    println(s"Receving SSH version from the server...")
    val buffer = collection.mutable.ArrayBuffer.empty[Byte]
    var lastByte: Int = -1
    var currentByte: Int = -1
    var serverVersion: String = null
    while (serverVersion == null && {
        currentByte = in.read; currentByte != -1
      }) {
      if (lastByte == 0x0d && currentByte == 0x0a) {
        buffer.trimEnd(1)
        serverVersion = new String(buffer.toArray)
        println(s"  serverSSHVersion = $serverVersion")
      }
      buffer += currentByte.toByte
      lastByte = currentByte
    }
    SSHSession.setServerVersion(serverVersion)
  }

  private def sendClientAlgorithms(): Unit = {
    println("SSH_MSG_KEXINIT(client -> server)...")
    write(clientAlrithms.generatePacket().getData)
  }

  private def receiveServerAlgorithms(): Unit = {
    println("SSH_MSG_KEXINIT(server -> client)...")
    serverAlgorithms = AlgorithmNegotiationPacket.readAlgorithmsFromInputStream(in)
    // println("Server algorithms: ")
    // println(serverAlgorithms)
  }

  private def clientKEX(): Unit = {
    write(DiffieHellmanGroup14Packet.generateDHInitPacket().getData)
  }

  private def serverKEX(): Unit = {
    DiffieHellmanGroup14Packet.readServerPublibKeyFromInputStream(in)
  }

  private def sendNewKey(): Unit = {
    println("Sending NEW_KEY...")
    write(NewKeyPacket.generatePacket())
  }

  private def receiveNewKey(): Unit = {
    println("Receving NEW_KEY...")
    NewKeyPacket.readNewKeyFromInputStream(in)
  }

  def receiveExtInfo(): Unit = {
    println("Receving extra info...")
    ExtInfoPacket.readExtInfoPacket(in)
  }

  private def sendAuthRequest(): Unit = {
    println("Sending auth request...")
    write(AuthPacket.generatePasswordUserAuthPacket("ihainan", "password").getData)
  }

  def closeConnection(): Unit = {
    if (socket != null) {
      socket.close()
    }
  }
}

object SimpleSSHClient extends App {
  val client = new SimpleSSHClient("localhost", 2222, "user", "password")
  // val client = new SimpleSSHClient("la.ihainan.me", 22, "user", "password")
  client.connect()
  client.closeConnection()
}
