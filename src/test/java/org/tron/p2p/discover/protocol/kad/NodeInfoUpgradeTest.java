package org.tron.p2p.discover.protocol.kad;

import com.google.common.primitives.Longs;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.tron.p2p.dns.tree.Algorithm;
import org.tron.p2p.protos.Discover;
import org.tron.p2p.utils.ByteArray;
import org.tron.p2p.utils.NetUtil;
import org.web3j.crypto.Keys;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class NodeInfoUpgradeTest {

  // signature data
  byte[] generateSignature(Discover.Endpoint endpoint, long timestamp, String privateKey, byte[] publicKey) {
    byte[] target = getRawDataTobeSigned(endpoint, timestamp, publicKey);
    return Algorithm.sigData(target, privateKey);
  }

  byte[] getRawDataTobeSigned(Discover.Endpoint endpoint, long timestamp, byte[] publicKey) {
    byte[] endpointBytes = generateEndpointBytes(endpoint);
    byte[] byteArray = Longs.toByteArray(timestamp);
    byte[] target = new byte[endpointBytes.length + publicKey.length + byteArray.length];
    System.arraycopy(endpointBytes, 0, target, 0, endpointBytes.length);
    System.arraycopy(publicKey, 0, target, endpointBytes.length, publicKey.length);
    System.arraycopy(byteArray, 0, target, endpointBytes.length + publicKey.length, byteArray.length);
    return target;
  }

  byte[] generateEndpointBytes(Discover.Endpoint endpoint) {
    byte[] port = Longs.toByteArray(endpoint.getPort());
    byte[] target = new byte[endpoint.getAddress().size() + port.length + endpoint.getNodeId().size() + endpoint.getAddressIpv6().size()];
    System.arraycopy(endpoint.getAddress().toByteArray(), 0, target, 0, endpoint.getAddress().size());
    System.arraycopy(port, 0, target, endpoint.getAddress().size(), port.length);
    System.arraycopy(endpoint.getNodeId().toByteArray(), 0, target, endpoint.getAddress().size() + port.length, endpoint.getNodeId().size());
    System.arraycopy(endpoint.getAddressIpv6().toByteArray(), 0, target, endpoint.getAddress().size() + port.length + endpoint.getNodeId().size(), endpoint.getAddressIpv6().size());
    return target;
  }


  boolean verifySignature(byte[] nodePubkeyArray, Discover.Endpoint from, long timestamp, byte[] nodeSig) throws SignatureException {
    byte[] target = getRawDataTobeSigned(from, timestamp, nodePubkeyArray);
    return Algorithm.verifySignature(new String(nodePubkeyArray), target, nodeSig);
  }

  @Test
  public void testPingVerifySignature() throws InvalidProtocolBufferException, SignatureException {
    String privateKey = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291";
    Discover.PingMessage pingMessage = getPingMessage(true, privateKey);
    byte[] byteArray = pingMessage.toByteArray();
    Discover.PingMessage parsedPingMessage = Discover.PingMessage.parseFrom(byteArray);
    byte[] nodePubkeyArray = pingMessage.getNodePubkey().toByteArray();
    boolean verified = verifySignature(nodePubkeyArray, parsedPingMessage.getFrom(), parsedPingMessage.getTimestamp(), pingMessage.getNodeSig().toByteArray());
    Assert.assertTrue(verified);
  }

  Discover.PingMessage getPingMessage(boolean withNewColumn, String privateKey) {
    Discover.Endpoint endpoint = getEndpoint();
    long timestamp = Long.MAX_VALUE;
    Discover.PingMessage.Builder builder = Discover.PingMessage.newBuilder().setFrom(endpoint).setTimestamp(timestamp);
    if (withNewColumn) {
      byte[] pubkeyArray = Algorithm.generateKeyPair(privateKey).getPublicKey().toByteArray();
      pubkeyArray = Hex.encode(pubkeyArray);
      byte[] signature = generateSignature(endpoint, timestamp, privateKey, pubkeyArray);
      return builder.setNodePubkey(ByteString.copyFrom(pubkeyArray))
          .setNodeSig(ByteString.copyFrom(signature)).build();
    } else {
      return builder.build();
    }
  }

  // signature data
  byte[] generateSignature(String privateKey, byte[] data) {
    return Algorithm.sigData(data, privateKey);
  }

  @Test
  public void testxxx() {
    String privateKey = "746e73991e265e6c1825677cc9f3b34c9feae8c2e6db82b72464d17d2d6222c1";
    byte[] byteArray = Algorithm.generateKeyPair(privateKey).getPublicKey().toByteArray();
    System.out.println(Hex.toHexString(byteArray));
  }

  Discover.PongMessage getPongMessage(boolean withNewColumn, String privateKey) {
    Discover.Endpoint endpoint = getEndpoint();
    long timestamp = Long.MAX_VALUE;
    Discover.PongMessage.Builder builder = Discover.PongMessage.newBuilder().setFrom(endpoint).setTimestamp(timestamp)
        .setEcho(Integer.MAX_VALUE);
    if (withNewColumn) {
      byte[] pubkeyArray = Algorithm.generateKeyPair(privateKey).getPublicKey().toByteArray();
      pubkeyArray = Hex.encode(pubkeyArray);
      byte[] signature = generateSignature(endpoint, timestamp, privateKey, pubkeyArray);
      return builder.setNodePubkey(ByteString.copyFrom(pubkeyArray))
          .setNodeSig(ByteString.copyFrom(signature)).build();
    } else {
      return builder.build();
    }
  }

  private static Discover.Endpoint getEndpoint() {
    byte[] nodeIds = new byte[64];
    Arrays.fill(nodeIds, (byte) 67);
    Discover.Endpoint endpoint = Discover.Endpoint.newBuilder()
        .setAddress(ByteString.copyFrom("127.0.0.1".getBytes()))
        .setPort(50051)
        .setNodeId(ByteString.copyFrom(nodeIds))
        .setAddressIpv6(ByteString.copyFrom("2400:8901::f03c:95ff:fecc:6122".getBytes()))
        .build();
    return endpoint;
  }


  Discover.FindNeighbours getFindNodeMessage(boolean withNewColumn, String privateKey) {
    Discover.Endpoint endpoint = getEndpoint();
    long timestamp = Long.MAX_VALUE;
    Discover.FindNeighbours.Builder builder = Discover.FindNeighbours.newBuilder().setFrom(endpoint).setTimestamp(timestamp)
        .setTargetId(endpoint.getAddress());
    if (withNewColumn) {
      byte[] pubkeyArray = Algorithm.generateKeyPair(privateKey).getPublicKey().toByteArray();
      pubkeyArray = Hex.encode(pubkeyArray);
      byte[] signature = generateSignature(endpoint, timestamp, privateKey, pubkeyArray);
      return builder.setNodePubkey(ByteString.copyFrom(pubkeyArray))
          .setNodeSig(ByteString.copyFrom(signature)).build();
    } else {
      return builder.build();
    }
  }

  Discover.Neighbours getNeighboursMessage(boolean withNewColumn, String privateKey) {
    Discover.Endpoint endpoint = getEndpoint();
    List<Discover.Endpoint> neighbours = new ArrayList<>();
    for (int i = 0; i < 16; i++) {
      neighbours.add(endpoint);
    }
    long timestamp = Long.MAX_VALUE;
    Discover.Neighbours.Builder builder = Discover.Neighbours.newBuilder().setFrom(endpoint).setTimestamp(timestamp)
        .addAllNeighbours(neighbours);
    if (withNewColumn) {
      byte[] pubkeyArray = Algorithm.generateKeyPair(privateKey).getPublicKey().toByteArray();
      pubkeyArray = Hex.encode(pubkeyArray);
      byte[] signature = generateSignature(endpoint, timestamp, privateKey, pubkeyArray);
      return builder.setNodePubkey(ByteString.copyFrom(pubkeyArray))
          .setNodeSig(ByteString.copyFrom(signature)).build();
    } else {
      return builder.build();
    }

  }


  @Test
  public void testVerifySignatureSize() {
    String privateKey = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291";
    int pingSize = getPingMessage(false, privateKey).getSerializedSize();
    int pingSize2 = getPingMessage(true, privateKey).getSerializedSize();

    int pongSize = getPongMessage(false, privateKey).getSerializedSize();
    int pongSize2 = getPongMessage(true, privateKey).getSerializedSize();
    int findNodeSize = getFindNodeMessage(false, privateKey).getSerializedSize();
    int findNodeSize2 = getFindNodeMessage(true, privateKey).getSerializedSize();
    Discover.Neighbours neighboursMessage = getNeighboursMessage(false, privateKey);
    byte[] byteArray = neighboursMessage.toByteArray();
    byte[] signature = generateSignature(privateKey, byteArray);
    int neighboursSize = getNeighboursMessage(false, privateKey).getSerializedSize();
    int neighboursSize2 = getNeighboursMessage(true, privateKey).getSerializedSize();

    System.out.println("ping size: " + pingSize);
    System.out.println("ping size2: " + pingSize2);
    System.out.println("pong size: " + pongSize);
    System.out.println("pong size2: " + pongSize2);
    System.out.println("findNode size: " + findNodeSize);
    System.out.println("findNode size2: " + findNodeSize2);
    System.out.println("neighbours size: " + neighboursSize);
    System.out.println("neighbours byteArray size: " + byteArray.length);
    System.out.println("neighbours signature size: " + signature.length);
    System.out.println("neighbours size2: " + neighboursSize2);
  }

  @Test
  public void testWritePrivateKeyTxt() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
    int num = 1000000;
    List<String> privateKeys = new ArrayList<>();

    for (int i = 0; i < num; i++) {
      String hexString = ByteArray.toHexString(Keys.createEcKeyPair().getPrivateKey().toByteArray());
      privateKeys.add(hexString);
    }

    try (FileWriter writer = new FileWriter("private_keys.txt")) {
      for (String key : privateKeys) {
        writer.write(key + "\n");
      }
      System.out.println("write success to file=private_keys.txt");
    } catch (IOException e) {
      e.printStackTrace();
    }
  }


  public List<String> loadPrivateKeys(int maxNum) {
    List<String> privateKeys = new ArrayList<>();
    try (BufferedReader br = new BufferedReader(new FileReader("private_keys.txt"))) {
      String line;
      while ((line = br.readLine()) != null) {
        privateKeys.add(line);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
    if (privateKeys.size() > maxNum) {
      return privateKeys.subList(0, maxNum);
    }
    System.out.println("privateKeys size: " + privateKeys.size());
    return privateKeys;
  }

  @Test
  public void testSignaturePerformance() throws InterruptedException {
    boolean withNewColumn = false;
    List<String> privateKeys = loadPrivateKeys(200000);
    int numThreads = Runtime.getRuntime().availableProcessors();
    ExecutorService executor = Executors.newFixedThreadPool(numThreads);


    AtomicLong totalGenTimePing = new AtomicLong();
    AtomicLong totalGenTimePong = new AtomicLong();
    AtomicLong totalGenTimeFindNode = new AtomicLong();
    AtomicLong totalGenTimeNeighbours = new AtomicLong();

    AtomicLong totalVerifyTimePing = new AtomicLong();
    AtomicLong totalVerifyTimePong = new AtomicLong();
    AtomicLong totalVerifyTimeFindNode = new AtomicLong();
    AtomicLong totalVerifyTimeNeighbours = new AtomicLong();


    CountDownLatch latch = new CountDownLatch(privateKeys.size());

    AtomicInteger completedTasks = new AtomicInteger(0);
    int totalTasks = privateKeys.size();

    for (int i = 0; i < privateKeys.size(); i++) {
      String privateKey = privateKeys.get(i);
      final int index = i % 4; // 轮流选择不同的消息类型


      CompletableFuture.runAsync(() -> {
        try {

          Discover.PingMessage pingMessage = null;
          Discover.PongMessage pongMessage = null;
          Discover.FindNeighbours findNodeMessage = null;
          Discover.Neighbours neighboursMessage = null;

          long genStart = System.nanoTime();
          if (index == 0) {
            pingMessage = getPingMessage(withNewColumn, privateKey);
          } else if (index == 1) {
            pongMessage = getPongMessage(withNewColumn, privateKey);
          } else if (index == 2) {
            findNodeMessage = getFindNodeMessage(withNewColumn, privateKey);
          } else {
            neighboursMessage = getNeighboursMessage(withNewColumn, privateKey);
          }
          long genEnd = System.nanoTime();

          long verifyStart = System.nanoTime();
          boolean verified;
          try {
            if (withNewColumn) {

              if (index == 0) {
                verified = verifySignature(
                    pingMessage.getNodePubkey().toByteArray(),
                    pingMessage.getFrom(),
                    pingMessage.getTimestamp(),
                    pingMessage.getNodeSig().toByteArray()
                );
              } else if (index == 1) {
                verified = verifySignature(
                    pongMessage.getNodePubkey().toByteArray(),
                    pongMessage.getFrom(),
                    pongMessage.getTimestamp(),
                    pongMessage.getNodeSig().toByteArray()
                );
              } else if (index == 2) {
                verified = verifySignature(
                    findNodeMessage.getNodePubkey().toByteArray(),
                    findNodeMessage.getFrom(),
                    findNodeMessage.getTimestamp(),
                    findNodeMessage.getNodeSig().toByteArray()
                );
              } else {
                verified = verifySignature(
                    neighboursMessage.getNodePubkey().toByteArray(),
                    neighboursMessage.getFrom(),
                    neighboursMessage.getTimestamp(),
                    neighboursMessage.getNodeSig().toByteArray()
                );
              }
            } else {
              verified = true;
            }
          } catch (SignatureException e) {
            throw new RuntimeException(e);
          }
          long verifyEnd = System.nanoTime();

          if (!verified) {
            throw new RuntimeException("Signature verification failed for key: " + privateKey);
          }

          // 统计不同消息类型的耗时
          if (index == 0) {
            totalGenTimePing.addAndGet(genEnd - genStart);
            totalVerifyTimePing.addAndGet(verifyEnd - verifyStart);
          } else if (index == 1) {
            totalGenTimePong.addAndGet(genEnd - genStart);
            totalVerifyTimePong.addAndGet(verifyEnd - verifyStart);
          } else if (index == 2) {
            totalGenTimeFindNode.addAndGet(genEnd - genStart);
            totalVerifyTimeFindNode.addAndGet(verifyEnd - verifyStart);
          } else {
            totalGenTimeNeighbours.addAndGet(genEnd - genStart);
            totalVerifyTimeNeighbours.addAndGet(verifyEnd - verifyStart);
          }


          int done = completedTasks.incrementAndGet();
          if (done % (totalTasks / 10) == 0 || done == totalTasks) {
            System.out.println("Progress: " + (done * 100 / totalTasks) + "% (" + done + "/" + totalTasks + ")");
          }
        } finally {
          latch.countDown();
        }
      }, executor);
    }
    latch.await();
    executor.shutdown();

    System.out.println("✅ Test Completed!");
    System.out.println("\n===== Average Generation Time (ms) =====");
    System.out.println("Ping: " + (totalGenTimePing.get() / (totalTasks / 4)) / 1_000_000.0);
    System.out.println("Pong: " + (totalGenTimePong.get() / (totalTasks / 4)) / 1_000_000.0);
    System.out.println("FindNode: " + (totalGenTimeFindNode.get() / (totalTasks / 4)) / 1_000_000.0);
    System.out.println("Neighbours: " + (totalGenTimeNeighbours.get() / (totalTasks / 4)) / 1_000_000.0);

    System.out.println("\n===== Average Verification Time (ms) =====");
    System.out.println("Ping: " + (totalVerifyTimePing.get() / (totalTasks / 4)) / 1_000_000.0);
    System.out.println("Pong: " + (totalVerifyTimePong.get() / (totalTasks / 4)) / 1_000_000.0);
    System.out.println("FindNode: " + (totalVerifyTimeFindNode.get() / (totalTasks / 4)) / 1_000_000.0);
    System.out.println("Neighbours: " + (totalVerifyTimeNeighbours.get() / (totalTasks / 4)) / 1_000_000.0);
  }


  @Test
  public void testAverageTimeForNodeIdGenerationAndKeyPairCreation() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
    int num = 1000000;

    // 计算获取 NodeId 耗时
    long totalNodeIdTime = 0;
    for (int i = 0; i < num; i++) {
      long startTime = System.nanoTime();
      NetUtil.getNodeId();
      long endTime = System.nanoTime();
      totalNodeIdTime += (endTime - startTime);
    }
    double avgNodeIdTime = totalNodeIdTime / (double) num / 1_000_000.0;  // 转换为毫秒
    System.out.println("Average time for getNodeId: " + avgNodeIdTime + " ms");

    // 计算创建密钥对耗时
    long totalKeyGenerationTime = 0;
    for (int i = 0; i < num; i++) {
      long startTime = System.nanoTime();
      Keys.createEcKeyPair().getPrivateKey();
      long endTime = System.nanoTime();
      totalKeyGenerationTime += (endTime - startTime);
    }
    double avgKeyGenerationTime = totalKeyGenerationTime / (double) num / 1_000_000.0;  // 转换为毫秒
    System.out.println("Average time for key generation: " + avgKeyGenerationTime + " ms");
  }


  @Test
  public void testSignaturePerformance2() throws InterruptedException {
    boolean withNewColumn = false;
    List<String> privateKeys = loadPrivateKeys(200000);
    int numThreads = Runtime.getRuntime().availableProcessors();
    ExecutorService executor = Executors.newFixedThreadPool(numThreads);

    AtomicLong totalGenTimePing = new AtomicLong();
    AtomicLong totalGenTimePong = new AtomicLong();
    AtomicLong totalGenTimeFindNode = new AtomicLong();
    AtomicLong totalGenTimeNeighbours = new AtomicLong();

    AtomicLong totalVerifyTimePing = new AtomicLong();
    AtomicLong totalVerifyTimePong = new AtomicLong();
    AtomicLong totalVerifyTimeFindNode = new AtomicLong();
    AtomicLong totalVerifyTimeNeighbours = new AtomicLong();

    CountDownLatch latch = new CountDownLatch(privateKeys.size());

    AtomicInteger completedTasks = new AtomicInteger(0);
    int totalTasks = privateKeys.size();

    for (int i = 0; i < privateKeys.size(); i++) {
      String privateKey = privateKeys.get(i);
      final int index = i % 4; // 轮流选择不同的消息类型
      CompletableFuture.runAsync(() -> {
        try {
          byte[] pingMessageBytes = null;
          byte[] pongMessageBytes = null;
          byte[] findNodeMessageBytes = null;
          byte[] neighboursMessageBytes = null;

          Discover.PingMessage pingMessage;
          Discover.PongMessage pongMessage;
          Discover.FindNeighbours findNodeMessage;
          Discover.Neighbours neighboursMessage;


          byte[] pingMessageSigBytes = null;
          byte[] pongMessageSigBytes = null;
          byte[] findNodeMessageSigBytes = null;
          byte[] neighboursMessageSigBytes = null;


          long genStart = System.nanoTime();
          if (index == 0) {
            pingMessage = getPingMessage(withNewColumn, privateKey);
            pingMessageBytes = pingMessage.toByteArray();
            pingMessageSigBytes = generateSignature(privateKey, pingMessageBytes);

          } else if (index == 1) {
            pongMessage = getPongMessage(withNewColumn, privateKey);
            pongMessageBytes = pongMessage.toByteArray();
            pongMessageSigBytes = generateSignature(privateKey, pongMessageBytes);
          } else if (index == 2) {
            findNodeMessage = getFindNodeMessage(withNewColumn, privateKey);
            findNodeMessageBytes = findNodeMessage.toByteArray();
            findNodeMessageSigBytes = generateSignature(privateKey, findNodeMessageBytes);
          } else {
            neighboursMessage = getNeighboursMessage(withNewColumn, privateKey);
            neighboursMessageBytes = neighboursMessage.toByteArray();
            neighboursMessageSigBytes = generateSignature(privateKey, neighboursMessageBytes);
          }
          long genEnd = System.nanoTime();

          boolean verified;
          byte[] pubkeyArray = Algorithm.generateKeyPair(privateKey).getPublicKey().toByteArray();
          pubkeyArray = Hex.encode(pubkeyArray);
          long verifyStart = System.nanoTime();
          try {
            if (index == 0) {
              verified = Algorithm.verifySignature(new String(pubkeyArray), pingMessageBytes, pingMessageSigBytes);
            } else if (index == 1) {
              verified = Algorithm.verifySignature(new String(pubkeyArray), pongMessageBytes, pongMessageSigBytes);
            } else if (index == 2) {
              verified = Algorithm.verifySignature(new String(pubkeyArray), findNodeMessageBytes, findNodeMessageSigBytes);
            } else {
              verified = Algorithm.verifySignature(new String(pubkeyArray), neighboursMessageBytes, neighboursMessageSigBytes);
            }
          } catch (SignatureException e) {
            throw new RuntimeException(e);
          }
          long verifyEnd = System.nanoTime();

          if (!verified) {
            throw new RuntimeException("Signature verification failed for key: " + privateKey);
          }

          // 统计不同消息类型的耗时
          if (index == 0) {
            totalGenTimePing.addAndGet(genEnd - genStart);
            totalVerifyTimePing.addAndGet(verifyEnd - verifyStart);
          } else if (index == 1) {
            totalGenTimePong.addAndGet(genEnd - genStart);
            totalVerifyTimePong.addAndGet(verifyEnd - verifyStart);
          } else if (index == 2) {
            totalGenTimeFindNode.addAndGet(genEnd - genStart);
            totalVerifyTimeFindNode.addAndGet(verifyEnd - verifyStart);
          } else {
            totalGenTimeNeighbours.addAndGet(genEnd - genStart);
            totalVerifyTimeNeighbours.addAndGet(verifyEnd - verifyStart);
          }
          int done = completedTasks.incrementAndGet();
          if (done % (totalTasks / 10) == 0 || done == totalTasks) {
            System.out.println("Progress: " + (done * 100 / totalTasks) + "% (" + done + "/" + totalTasks + ")");
          }
        } finally {
          latch.countDown();
        }
      }, executor);
    }
    latch.await();
    executor.shutdown();

    System.out.println("✅ Test Completed!");
    System.out.println("\n===== Average Generation Time (ms) =====");
    System.out.println("Ping: " + (totalGenTimePing.get() / (totalTasks / 4)) / 1_000_000.0);
    System.out.println("Pong: " + (totalGenTimePong.get() / (totalTasks / 4)) / 1_000_000.0);
    System.out.println("FindNode: " + (totalGenTimeFindNode.get() / (totalTasks / 4)) / 1_000_000.0);
    System.out.println("Neighbours: " + (totalGenTimeNeighbours.get() / (totalTasks / 4)) / 1_000_000.0);

    System.out.println("\n===== Average Verification Time (ms) =====");
    System.out.println("Ping: " + (totalVerifyTimePing.get() / (totalTasks / 4)) / 1_000_000.0);
    System.out.println("Pong: " + (totalVerifyTimePong.get() / (totalTasks / 4)) / 1_000_000.0);
    System.out.println("FindNode: " + (totalVerifyTimeFindNode.get() / (totalTasks / 4)) / 1_000_000.0);
    System.out.println("Neighbours: " + (totalVerifyTimeNeighbours.get() / (totalTasks / 4)) / 1_000_000.0);
  }
}
