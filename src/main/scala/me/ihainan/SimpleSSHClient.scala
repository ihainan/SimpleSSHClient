package me.ihainan

import java.net.Socket
import java.io.InputStream
import java.io.OutputStream
import scala.util.Random
import me.ihainan.utils.SSHBuffer
import me.ihainan.packets._
import me.ihainan.utils.SSHFormatter
import java.nio.channels.Channel
import org.slf4j.LoggerFactory

class SimpleSSHClient(
    val host: String,
    val port: Int,
    val username: String,
    val password: String
) {
  private val logger = LoggerFactory.getLogger(getClass().getName())

  private var socket: Socket = _
  private var in: InputStream = _
  private var out: OutputStream = _

  private val SSH_CLIENT_VERSON = "SSH-2.0-SimpleSSH_0.0.1"

  private val clientAlrithms = AlgorithmNegotiationPacket.getClientAlgorithms()
  private var serverAlgorithms: AlgorithmNegotiationPacket = _

  def write(bytes: Array[Byte]): Unit = {
    out.write(bytes)
    out.flush()
  }

  def createConnection(): Unit = {
    socket = new Socket(host, port)
    in = socket.getInputStream()
    out = socket.getOutputStream()
    logger.info("Connected to the server {}:{}", host, port)
  }

  def start(): Unit = {
    try {
      // connect to the server
      createConnection()

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

      // request for auth service
      sendServiceRequest("ssh-userauth")
      receiveServiceAccept()

      // auth using password
      sendAuthRequest(username, password)
      receivePasswordAuthenticationResponse()

      // create new session
      val channel = new ChannelPacket(in, out)
      val thread = channel.serverListenerThread()
      thread.start()
      thread.join()
    } finally {
      if (in != null) in.close()
      if (out != null) out.close()
      if (socket != null) socket.close()
    }
  }

  def sendClientVersion(): Unit = {
    logger.info(s"Sending SSH version to the server...")
    logger.info(s"  clientSSHVersion = $SSH_CLIENT_VERSON")
    val buffer = new SSHBuffer()
    buffer.putByteArray(SSH_CLIENT_VERSON.getBytes())
    buffer.putByteArray(Array(0x0d, 0x0a)) // CR LF
    write(buffer.getData)
    SSHSession.setClientVersion(SSH_CLIENT_VERSON)
  }

  def receiveServerVersion(): Unit = {
    logger.info(s"Receving SSH version from the server...")
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
        logger.info(s"  serverSSHVersion = $serverVersion")
      }
      buffer += currentByte.toByte
      lastByte = currentByte
    }
    SSHSession.setServerVersion(serverVersion)
  }

  private def sendClientAlgorithms(): Unit = {
    logger.info("SSH_MSG_KEXINIT(client -> server)...")
    write(clientAlrithms.generatePacket().getData)
  }

  private def receiveServerAlgorithms(): Unit = {
    logger.info("SSH_MSG_KEXINIT(server -> client)...")
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
    logger.info("Sending NEW_KEY packet...")
    write(NewKeyPacket.generatePacket())
  }

  private def receiveNewKey(): Unit = {
    logger.info("Receving NEW_KEY...")
    NewKeyPacket.readNewKeyFromInputStream(in)
  }

  private def receiveExtInfo(): Unit = {
    logger.info("Receving extra info...")
    ExtInfoPacket.readExtInfoPacket(in)
  }

  private def sendServiceRequest(service: String): Unit = {
    logger.info(s"Sending service request $service...")
    write(ServiceRequestPacket.generateServiceRequestPacket(service).getData)
  }

  private def receiveServiceAccept(): Unit = {
    logger.info(s"Receving service accept packet...")
    ServiceRequestPacket.receiveServiceAccept(in)
  }

  private def sendAuthRequest(username: String, password: String): Unit = {
    logger.info("Sending auth request...")
    write(AuthPacket.generatePasswordUserAuthPacket(username, password).getData)
  }

  private def receivePasswordAuthenticationResponse(): Unit = {
    logger.info("Receving auth response...")
    AuthPacket.readPasswordAuthenticationResponse(in)
  }

  def closeConnection(): Unit = {
    if (socket != null) {
      socket.close()
    }
  }
}

object SimpleSSHClient extends App {
  if (args.length < 4) {
    println("Usage: SimpleSSHClient <host> <port> <username> <password>")
    System.exit(1)
  }
  val client = new SimpleSSHClient(args(0), args(1).toInt, args(2), args(3))
  client.start()
}
