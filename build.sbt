ThisBuild / scalaVersion := "2.12.19"

name := "SimpleSSHClient"

libraryDependencies += "commons-codec" % "commons-codec" % "1.17.1"
libraryDependencies += "org.scalatest" %% "scalatest" % "3.3.0-SNAP4" % Test
libraryDependencies += "org.apache.logging.log4j" % "log4j-slf4j2-impl" % "2.23.1"
libraryDependencies += "org.slf4j" % "slf4j-api" % "2.0.13"
libraryDependencies += "org.apache.logging.log4j" % "log4j-core" % "2.23.1"
libraryDependencies += "org.apache.logging.log4j" % "log4j-api" % "2.23.1"
