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
import me.ihainan.algorithms.HelloPacket

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

  private val clientAlrithms = KeyExchangePacket.getClientAlgorithms()
  private var serverAlgorithms: KeyExchangePacket = _

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

      // close connection
      closeConnection()
    } finally {
      if (in != null) in.close()
      if (out != null) out.close()
      if (socket != null) socket.close()
    }
  }

  def sendClientVersion(): Unit = {
    logger.info(s"Sending SSH version to the server...")
    write(HelloPacket.generateVersionPacket().getData)
  }

  def receiveServerVersion(): Unit = {
    logger.info(s"Receving SSH version from the server...")
    HelloPacket.receiveServerVersionPacket(in)
  }

  private def sendClientAlgorithms(): Unit = {
    logger.info("SSH_MSG_KEXINIT(client -> server)...")
    logger.info("Client's algorithms: \n{}", clientAlrithms.toString(): Any)
    write(clientAlrithms.generatePacket().getData)
  }

  private def receiveServerAlgorithms(): Unit = {
    logger.info("SSH_MSG_KEXINIT(server -> client)...")
    serverAlgorithms = KeyExchangePacket.readAlgorithmsFromInputStream(in)
    logger.info("server's algorithms: \n{}", serverAlgorithms.toString(): Any)
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
    Thread.sleep(100)
    while (in.available() != 0) {
      ExtInfoPacket.readExtInfoPacket(in)
      Thread.sleep(100)
    }
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

  private def closeConnection(): Unit = {
    logger.info("Closing connection...")
    write(DisconnectPacket.generateDisconnectPacket().getData)
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
