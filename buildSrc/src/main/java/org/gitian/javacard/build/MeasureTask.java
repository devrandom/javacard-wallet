package org.gitian.javacard.build;

import apdu4j.APDUBIBO;
import apdu4j.CommandAPDU;
import apdu4j.ResponseAPDU;
import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.logging.Logger;
import org.gradle.api.tasks.TaskAction;

import javax.smartcardio.CardException;
import java.io.IOException;
import java.util.Arrays;

import static java.lang.System.currentTimeMillis;
import static pro.javacard.gp.GPException.check;

public class MeasureTask extends DefaultTask {
  private static final int ITERATIONS = 10;
  private final Logger logger;
  private APDUBIBO channel;
  private Card card;

  public MeasureTask() {
    logger = getLogger();
  }

  @TaskAction
  public void measure() {
    card = new Card();
    try {
      card.open();
    } catch (CardException e) {
      throw new GradleException("Error opening card", e);
    }

    channel = card.getChannel();

    try {
      logger.info("Selecting the applet");
      select();
      logger.info("Ping");
      do_ping();
      logger.info("EC");
      do_ec();
      logger.info("Success");
    } catch (IOException e) {
      throw new GradleException("I/O error", e);
    } finally {
      card.close();
    }
  }

  private void select() throws IOException {
    card.select(Identifiers.HELLOWORLD_AID);
  }

  private void do_ping() throws IOException {
    CommandAPDU cmd = new CommandAPDU(0x80, 0x00, 0, 0, new byte[0]);
    ResponseAPDU result = check(channel.transmit(cmd));
    if (!Arrays.equals(result.getData(), "Hello".getBytes())) {
      throw new IOException("did not get Hello");
    }
  }

  private void do_ec() throws IOException {
    time("sign", 0x01);
    time("pub", 0x02);
    time("derive priv", 0x03);
  }

  private void time(String name, int task) throws IOException {
    long startTime = currentTimeMillis();
    CommandAPDU cmd = new CommandAPDU(0x80, task, 0, 0, new byte[0]);
    check(channel.transmit(cmd));
    long warmTime = currentTimeMillis();
    cmd = new CommandAPDU(0x80, task, ITERATIONS, 0, new byte[0]);
    check(channel.transmit(cmd));
    long fullTime = currentTimeMillis();

    logger.info("{} warm {}ms loop {}ms", name, warmTime - startTime, fullTime - warmTime);
    logger.info("{} in average {}ms", name, (fullTime - warmTime - (warmTime - startTime)) / ITERATIONS);
  }
}
