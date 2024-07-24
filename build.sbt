ThisBuild / scalaVersion := "2.12.15"

name := "SimpleSSHClient"

libraryDependencies += "commons-codec" % "commons-codec" % "1.17.1"
libraryDependencies += "org.scalatest" %% "scalatest" % "3.3.0-SNAP4" % Test
libraryDependencies += "org.bouncycastle" % "bcprov-jdk15on" % "1.70"