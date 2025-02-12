package org.tron.p2p.discover.protocol.kad;

import com.google.common.primitives.Longs;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.junit.Assert;
import org.junit.Test;
import org.tron.p2p.dns.tree.Algorithm;
import org.tron.p2p.protos.Discover;
import org.tron.p2p.utils.ByteArray;

import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class NodeInfoUpgradeTest {

  // signature data
  byte[] generateSignature(Discover.Endpoint endpoint, long timestamp, String privateKey, String publicKey) {
    byte[] target = getRawDataTobeSigned(endpoint, timestamp, publicKey);
    return Algorithm.sigData(new String(target), privateKey);
  }

  byte[] getRawDataTobeSigned(Discover.Endpoint endpoint, long timestamp, String publicKey) {
    byte[] byteArray = Longs.toByteArray(timestamp);
    byte[] endpointBytes = generateEndpointBytes(endpoint);
    byte[] target = new byte[endpointBytes.length + publicKey.length() + byteArray.length];
    System.arraycopy(endpointBytes, 0, target, 0, endpointBytes.length);
    System.arraycopy(publicKey.getBytes(), 0, target, endpointBytes.length, publicKey.length());
    System.arraycopy(byteArray, 0, target, endpointBytes.length + publicKey.length(), byteArray.length);
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


  boolean verifySignature(Discover.PingMessage pingMessage) throws SignatureException {
    byte[] target = getRawDataTobeSigned(pingMessage.getFrom(), pingMessage.getTimestamp(), new String(pingMessage.getNodePubkey().toByteArray()));
    return Algorithm.verifySignature(new String(pingMessage.getNodePubkey().toByteArray()), new String(target), pingMessage.getNodeSig().toByteArray());
  }

  public static String privateKey = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291";

  @Test
  public void testPingVerifySignature() throws InvalidProtocolBufferException, SignatureException {

    Discover.PingMessage pingMessage = getPingMessage(true);
    byte[] byteArray = pingMessage.toByteArray();
    Discover.PingMessage parsedPingMessage = Discover.PingMessage.parseFrom(byteArray);
    boolean verified = verifySignature(parsedPingMessage);
    Assert.assertTrue(verified);
  }

  Discover.PingMessage getPingMessage(boolean withNewColumn) {
    Discover.Endpoint endpoint = getEndpoint();
    long timestamp = 2L;
    byte[] signature = generateSignature(endpoint, timestamp, privateKey, ByteArray.toHexString(Algorithm.generateKeyPair(privateKey).getPublicKey().toByteArray()));
    System.out.println("signature: " + ByteArray.toHexString(signature));
    Discover.PingMessage.Builder builder = Discover.PingMessage.newBuilder().setFrom(endpoint).setTimestamp(timestamp);
    if (withNewColumn) {
      return builder.setNodePubkey(ByteString.copyFrom(ByteArray.toHexString(Algorithm.generateKeyPair(privateKey).getPublicKey().toByteArray()).getBytes()))
          .setNodeSig(ByteString.copyFrom(signature)).build();
    } else {
      return builder.build();
    }
  }

  Discover.PongMessage getPongMessage(boolean withNewColumn) {
    Discover.Endpoint endpoint = getEndpoint();
    long timestamp = 2L;
    byte[] signature = generateSignature(endpoint, timestamp, privateKey, ByteArray.toHexString(Algorithm.generateKeyPair(privateKey).getPublicKey().toByteArray()));
    System.out.println("signature: " + ByteArray.toHexString(signature));

    Discover.PongMessage.Builder builder = Discover.PongMessage.newBuilder().setFrom(endpoint).setTimestamp(timestamp)
        .setEcho(Integer.MAX_VALUE);
    if (withNewColumn) {
      return builder.setNodePubkey(ByteString.copyFrom(ByteArray.toHexString(Algorithm.generateKeyPair(privateKey).getPublicKey().toByteArray()).getBytes()))
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


  Discover.FindNeighbours getFindNodeMessage(boolean withNewColumn) {
    Discover.Endpoint endpoint = getEndpoint();
    long timestamp = 2L;
    byte[] signature = generateSignature(endpoint, timestamp, privateKey, ByteArray.toHexString(Algorithm.generateKeyPair(privateKey).getPublicKey().toByteArray()));
    System.out.println("signature: " + ByteArray.toHexString(signature));
    Discover.FindNeighbours.Builder builder = Discover.FindNeighbours.newBuilder().setFrom(endpoint).setTimestamp(timestamp)
        .setTargetId(endpoint.getAddress());
    if (withNewColumn) {
      return builder.setNodePubkey(ByteString.copyFrom(ByteArray.toHexString(Algorithm.generateKeyPair(privateKey).getPublicKey().toByteArray()).getBytes()))
          .setNodeSig(ByteString.copyFrom(signature)).build();
    } else {
      return builder.build();
    }
  }

  Discover.Neighbours getNeighboursMessage(boolean withNewColumn) {
    Discover.Endpoint endpoint = getEndpoint();
    List<Discover.Endpoint> neighbours = new ArrayList<>();
    for (int i = 0; i < 16; i++) {
      neighbours.add(endpoint);
    }
    long timestamp = 2L;
    byte[] signature = generateSignature(endpoint, timestamp, privateKey, ByteArray.toHexString(Algorithm.generateKeyPair(privateKey).getPublicKey().toByteArray()));
    System.out.println("signature: " + ByteArray.toHexString(signature));
    Discover.Neighbours.Builder builder = Discover.Neighbours.newBuilder().setFrom(endpoint).setTimestamp(timestamp)
        .addAllNeighbours(neighbours);
    if (withNewColumn) {
      return builder.setNodePubkey(ByteString.copyFrom(ByteArray.toHexString(Algorithm.generateKeyPair(privateKey).getPublicKey().toByteArray()).getBytes()))
          .setNodeSig(ByteString.copyFrom(signature)).build();
    } else {
      return builder.build();
    }

  }


  @Test
  public void testVerifySignatureSize() {
    int pingSize = getPingMessage(false).getSerializedSize();
    int pingSize2 = getPingMessage(true).getSerializedSize();

    int pongSize = getPongMessage(false).getSerializedSize();
    int pongSize2 = getPongMessage(true).getSerializedSize();
    int findNodeSize = getFindNodeMessage(false).getSerializedSize();
    int findNodeSize2 = getFindNodeMessage(true).getSerializedSize();
    int neighboursSize = getNeighboursMessage(false).getSerializedSize();
    int neighboursSize2 = getNeighboursMessage(true).getSerializedSize();


    System.out.println("ping size: " + pingSize);
    System.out.println("ping size2: " + pingSize2);
    System.out.println("pong size: " + pongSize);
    System.out.println("pong size2: " + pongSize2);
    System.out.println("findNode size: " + findNodeSize);
    System.out.println("findNode size2: " + findNodeSize2);
    System.out.println("neighbours size: " + neighboursSize);
    System.out.println("neighbours size2: " + neighboursSize2);

  }
}
