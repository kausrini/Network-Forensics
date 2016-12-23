package forensics;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

public class NetworkForensics {

	public static final int MAX_CAPTURE_SIZE = 30000000;
	public static final int PCAP_HEADER_LENGTH = 24;
	public static final int PACKET_HEADER_LENGTH = 16;
	public static final int ETHERNET_HEADER_LENGTH = 14;
	// public static final int MAXIMUM_SEGMENT_SIZE = 65535;

	static class IpAddress {
		byte firstByte;
		byte secondByte;
		byte thirdByte;
		byte fourthByte;

		IpAddress() {
			firstByte = 0;
			secondByte = 0;
			thirdByte = 0;
			fourthByte = 0;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + firstByte;
			result = prime * result + fourthByte;
			result = prime * result + secondByte;
			result = prime * result + thirdByte;
			return result;
		}

		@Override
		public boolean equals(Object obj) {

			if (this.firstByte == ((IpAddress) obj).firstByte && this.secondByte == ((IpAddress) obj).secondByte
					&& this.thirdByte == ((IpAddress) obj).thirdByte
					&& this.fourthByte == ((IpAddress) obj).fourthByte) {

				return true;
			}

			return false;
		}

		@Override
		public String toString() {
			return Byte.toUnsignedInt(this.firstByte) + "." + Byte.toUnsignedInt(this.secondByte) + "."
					+ Byte.toUnsignedInt(this.thirdByte) + "." + Byte.toUnsignedInt(this.fourthByte);
		}

	}

	static class ConnectionTuple implements Comparable<Object> {
		IpAddress sourceIp;
		IpAddress destinationIp;
		int sourcePort;
		int destinationPort;
		int upDataLength;
		int downDataLength;

		ConnectionTuple() {
			sourceIp = new IpAddress();
			destinationIp = new IpAddress();
			sourcePort = 0;
			destinationPort = 0;
			upDataLength = 0;
			downDataLength = 0;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + destinationPort;
			result = prime * result + ((destinationIp == null) ? 0 : destinationIp.hashCode());
			result = prime * result + ((sourceIp == null) ? 0 : sourceIp.hashCode());
			result = prime * result + sourcePort;
			return result;
		}

		@Override
		public boolean equals(Object obj) {

			if (this.sourceIp.equals(((ConnectionTuple) obj).sourceIp)
					&& this.destinationIp.equals(((ConnectionTuple) obj).destinationIp)
					&& this.sourcePort == ((ConnectionTuple) obj).sourcePort
					&& this.destinationPort == ((ConnectionTuple) obj).destinationPort) {

				return true;

			}

			return false;
		}

		@Override
		public String toString() {
			return this.sourceIp + " " + this.sourcePort + " " + this.destinationIp + " " + this.destinationPort + " "
					+ this.upDataLength + " " + this.downDataLength;
		}

		@Override
		public int compareTo(Object o) {

			return this.toString().compareTo(((ConnectionTuple) o).toString());
		}

	}

	static class Packet {

		long sequenceNumber;
		long acknowledgementNumber;
		List<Byte> data;
		long captureTime;
		long microOffset;

		Packet() {
			this.sequenceNumber = 0L;
			this.acknowledgementNumber = 0L;
			this.captureTime = 0L;
			this.microOffset = 0L;
			this.data = new ArrayList<Byte>();
		}

	}

	static class TcpConnection {

		IpAddress source;
		IpAddress destination;
		int sport;
		int dport;
		int upDataLength;
		int downDataLength;
		List<Byte> upstreamData;
		List<Byte> downstreamData;
		// for task3
		// Packet upstreamPacket;
		// Packet downstreamPacket;

		List<Packet> upstreamPackets;
		List<Packet> downstreamPackets;

		TcpConnection() {
			this.source = new IpAddress();
			this.destination = new IpAddress();
			this.sport = this.dport = 0;
			this.upDataLength = 0;
			this.downDataLength = 0;
			this.upstreamData = new ArrayList<Byte>();
			this.downstreamData = new ArrayList<Byte>();

			// this.upstreamPacket = new Packet();
			// this.downstreamPacket = new Packet();

			this.upstreamPackets = new ArrayList<Packet>();
			this.downstreamPackets = new ArrayList<Packet>();

		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + destination.firstByte + destination.thirdByte;
			result = prime * result + dport;
			result = prime * result + source.secondByte + source.fourthByte;
			result = prime * result + sport;
			return result;
		}

		@Override
		public boolean equals(Object obj) {

			if ((this.destination.equals(((TcpConnection) obj).destination)
					&& this.source.equals(((TcpConnection) obj).source) && this.dport == ((TcpConnection) obj).dport
					&& this.sport == ((TcpConnection) obj).sport)) {

				return true;
			}

			if (this.destination.equals(((TcpConnection) obj).source)
					&& this.source.equals(((TcpConnection) obj).destination)
					&& this.sport == ((TcpConnection) obj).dport && this.dport == ((TcpConnection) obj).sport) {

				return true;
			}

			return false;
		}

	}

	static class HttpConnection implements Comparable<Object> {

		ConnectionTuple connection;

		String receptionTime;
		long captureTime;
		long microOffset;
		long responseBodyLength;
		long sequenceNumber;
		long acknowledgementNumber;
		long contentLength;

		String requestedUrl;
		String hostname;
		int responseCode;

		List<Byte> responseData;
		String imageType;

		HttpConnection() {
			this.receptionTime = new String();
			this.requestedUrl = new String();
			this.responseBodyLength = 0L;
			this.captureTime = 0L;
			this.microOffset = 0L;
			this.hostname = new String();
			this.responseCode = 0;
			this.contentLength = 0;

			this.responseData = new ArrayList<Byte>();
			this.imageType = new String();
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + (int) (acknowledgementNumber ^ (acknowledgementNumber >>> 32));
			result = prime * result + (int) (contentLength ^ (contentLength >>> 32));
			result = prime * result + ((hostname == null) ? 0 : hostname.hashCode());
			result = prime * result + ((receptionTime == null) ? 0 : receptionTime.hashCode());
			result = prime * result + ((requestedUrl == null) ? 0 : requestedUrl.hashCode());
			result = prime * result + (int) (responseBodyLength ^ (responseBodyLength >>> 32));
			result = prime * result + responseCode;
			result = prime * result + (int) (sequenceNumber ^ (sequenceNumber >>> 32));
			return result;
		}

		@Override
		public boolean equals(Object obj) {

			if (this == obj)
				return true;
			return false;
		}

		@Override
		public int compareTo(Object obj) {

			// String captureTime = o.receptionTime.substring(0,
			// o.receptionTime.indexOf(" "));
			// String microOffset =
			// o.receptionTime.substring(o.receptionTime.indexOf(" ") + 1);

			HttpConnection o = (HttpConnection) obj;

			if (this.captureTime == o.captureTime) {
				return (int) (this.microOffset - o.microOffset);
			} else {
				return (int) (this.captureTime - o.captureTime);
			}

			/*
			 * if (this.receptionTime.substring(0, this.receptionTime.indexOf(
			 * " ")).compareTo(captureTime) == 0) return
			 * this.receptionTime.substring(this.receptionTime.indexOf(" ") +
			 * 1).compareTo(microOffset); else return
			 * this.receptionTime.substring(0, this.receptionTime.indexOf(" "
			 * )).compareTo(captureTime);
			 */
		}

		public static Comparator<HttpConnection> HttpConnectionComparator = new Comparator<HttpConnection>() {

			@Override
			public int compare(HttpConnection o1, HttpConnection o2) {
				if (o1.captureTime == o2.captureTime) {
					return (int) (o1.microOffset - o2.microOffset);
				} else {
					return (int) (o1.captureTime - o2.captureTime);
				}
			}

		};

	}

	static int input(byte[] captureData) {

		int captureSize = 0;
		InputStream d = new DataInputStream(System.in);

		try {
			int v = d.read();
			while (v != -1) {

				captureData[captureSize++] = (byte) v;

				v = d.read();

			}
		} catch (IOException e) {
			System.out.println("Input error in parsing PCAP file");
		}

		return captureSize;

	}

	static void task1(byte[] captureData, int captureSize) {

		int totalPacketCount = 0;
		int ipPacketCount = 0;
		int tcpPacketCount = 0;
		int udpPacketCount = 0;
		int tcpConnectionsCount = 0;
		Map<TcpConnection, Integer> TcpConnectionsTable = new HashMap<TcpConnection, Integer>();

		// The Pcap file header is 24 bytes.
		// Packet headers are 16 bytes.
		// To count total number of packets need to count the number of packet
		// headers.
		// Ethernet header is 14 bytes
		// Upper layer protocol of ipv4 is in 9th byte of ethernet header

		// i in the loop points to the start of packet payload.
		for (int i = PCAP_HEADER_LENGTH + PACKET_HEADER_LENGTH; i < captureSize;) {

			// Converting 4 bytes of data into a single integer
			int totalPacketLength = Byte.toUnsignedInt(captureData[i - 1]);
			totalPacketLength <<= 8;
			totalPacketLength |= Byte.toUnsignedInt(captureData[i - 2]);
			totalPacketLength <<= 8;
			totalPacketLength |= Byte.toUnsignedInt(captureData[i - 3]);
			totalPacketLength <<= 8;
			totalPacketLength |= Byte.toUnsignedInt(captureData[i - 4]);

			// i+12 is specifies the length (if<1500) or type ethernet frame
			// header
			int frameType = Byte.toUnsignedInt(captureData[i + 12]);
			frameType <<= 8;
			frameType |= Byte.toUnsignedInt(captureData[i + 13]);

			if (frameType == 2048) { // ipv4 packet
				ipPacketCount++;

				// i+ETHERNET_HEADER_LENGTH is the start of IP Packet
				int ipHeaderLength = Byte.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH]);
				// But only last 4 bits is the length
				ipHeaderLength &= 15;// Removes first 4 bits
				ipHeaderLength *= 4; // The length is specified as 32bit words

				if (Byte.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + 9]) == 6) { // TCP
					// packet
					tcpPacketCount++;

					TcpConnection tcpConnection = new TcpConnection();

					tcpConnection.source.firstByte = captureData[i + ETHERNET_HEADER_LENGTH + 12];
					tcpConnection.source.secondByte = captureData[i + ETHERNET_HEADER_LENGTH + 13];
					tcpConnection.source.thirdByte = captureData[i + ETHERNET_HEADER_LENGTH + 14];
					tcpConnection.source.fourthByte = captureData[i + ETHERNET_HEADER_LENGTH + 15];

					tcpConnection.destination.firstByte = captureData[i + ETHERNET_HEADER_LENGTH + 16];
					tcpConnection.destination.secondByte = captureData[i + ETHERNET_HEADER_LENGTH + 17];
					tcpConnection.destination.thirdByte = captureData[i + ETHERNET_HEADER_LENGTH + 18];
					tcpConnection.destination.fourthByte = captureData[i + ETHERNET_HEADER_LENGTH + 19];

					int sourcePort = Byte.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength]);
					sourcePort <<= 8;
					sourcePort |= Byte.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 1]);

					int destinationPort = Byte
							.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 2]);
					destinationPort <<= 8;
					destinationPort |= Byte.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 3]);

					tcpConnection.sport = sourcePort;
					tcpConnection.dport = destinationPort;

					TcpConnection reverseTcpConnection = new TcpConnection();
					reverseTcpConnection.source = tcpConnection.destination;
					reverseTcpConnection.destination = tcpConnection.source;
					reverseTcpConnection.sport = tcpConnection.dport;
					reverseTcpConnection.dport = tcpConnection.sport;

					if (TcpConnectionsTable.containsKey(tcpConnection)
							|| TcpConnectionsTable.containsKey(reverseTcpConnection)) {
						// If tcp connection exists its not unique
					} else {
						TcpConnectionsTable.put(tcpConnection, 1);

						tcpConnectionsCount++;
					}
				} else if (Byte.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + 9]) == 17) { // UDP
					// packet
					udpPacketCount++;
				}
			}
			totalPacketCount++;
			i += totalPacketLength + PACKET_HEADER_LENGTH;
		}

		System.out.print(totalPacketCount + " " + ipPacketCount + " " + tcpPacketCount + " " + udpPacketCount + " "
				+ tcpConnectionsCount + "\n");

	}

	static void task2(byte[] captureData, int captureSize) {

		Map<ConnectionTuple, TcpConnection> TcpConnectionsTable = new HashMap<ConnectionTuple, TcpConnection>();
		Map<ConnectionTuple, TcpConnection> sortedTcpConnectionsTable = new TreeMap<ConnectionTuple, TcpConnection>();

		// The Pcap file header is 24 bytes.
		// Packet headers are 16 bytes.
		// To count total number of packets need to count the number of packet
		// headers.
		// Ethernet header is 14 bytes
		// Upper layer protocol of ipv4 is in 9th byte of ethernet header
		// i in the loop points to the start of packet payload.
		for (int i = PCAP_HEADER_LENGTH + PACKET_HEADER_LENGTH; i < captureSize;) {
			// Converting 4 bytes of data into a single integer
			int totalPacketLength = Byte.toUnsignedInt(captureData[i - 1]);
			totalPacketLength <<= 8;
			totalPacketLength |= Byte.toUnsignedInt(captureData[i - 2]);
			totalPacketLength <<= 8;
			totalPacketLength |= Byte.toUnsignedInt(captureData[i - 3]);
			totalPacketLength <<= 8;
			totalPacketLength |= Byte.toUnsignedInt(captureData[i - 4]);

			// i+12 is specifies the length (if<1500) or type ethernet frame
			// header
			int frameType = Byte.toUnsignedInt(captureData[i + 12]);
			frameType <<= 8;
			frameType |= Byte.toUnsignedInt(captureData[i + 13]);

			if (frameType == 2048) { // ipv4 packet

				// i+ETHERNET_HEADER_LENGTH is the start of IP Packet
				int ipHeaderLength = Byte.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH]);
				// But only last 4 bits is the length
				ipHeaderLength &= 15;// Removes first 4 bits

				ipHeaderLength *= 4; // The length is specified as 32bit words

				int ipTotalLength = Byte.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + 2]);
				ipTotalLength <<= 8;
				ipTotalLength |= Byte.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + 3]);

				if (Byte.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + 9]) == 6) { // TCP
					// packet

					TcpConnection tcpConnection;
					ConnectionTuple connection = new ConnectionTuple();
					ConnectionTuple revConnection = new ConnectionTuple();

					// first 4 bytes of 12th byte of TCP header is data offset
					int tcpHeaderLength = Byte
							.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 12]);
					tcpHeaderLength >>= 4;
					tcpHeaderLength *= 4; // 32bit words to bytes

					int tcpPayloadLength = ipTotalLength - ipHeaderLength - tcpHeaderLength;

					IpAddress temp = new IpAddress();
					temp.firstByte = captureData[i + ETHERNET_HEADER_LENGTH + 12];
					temp.secondByte = captureData[i + ETHERNET_HEADER_LENGTH + 13];
					temp.thirdByte = captureData[i + ETHERNET_HEADER_LENGTH + 14];
					temp.fourthByte = captureData[i + ETHERNET_HEADER_LENGTH + 15];
					connection.sourceIp = temp;

					temp = new IpAddress();
					temp.firstByte = captureData[i + ETHERNET_HEADER_LENGTH + 16];
					temp.secondByte = captureData[i + ETHERNET_HEADER_LENGTH + 17];
					temp.thirdByte = captureData[i + ETHERNET_HEADER_LENGTH + 18];
					temp.fourthByte = captureData[i + ETHERNET_HEADER_LENGTH + 19];
					connection.destinationIp = temp;

					connection.sourcePort = Byte
							.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength]);
					connection.sourcePort <<= 8;
					connection.sourcePort |= Byte
							.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 1]);

					connection.destinationPort = Byte
							.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 2]);
					connection.destinationPort <<= 8;
					connection.destinationPort |= Byte
							.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 3]);

					revConnection.destinationIp = connection.sourceIp;
					revConnection.sourceIp = connection.destinationIp;
					revConnection.sourcePort = connection.destinationPort;
					revConnection.destinationPort = connection.sourcePort;

					if (TcpConnectionsTable.containsKey(connection)) {

						tcpConnection = TcpConnectionsTable.get(connection);

					} else if (TcpConnectionsTable.containsKey(revConnection)) {

						tcpConnection = TcpConnectionsTable.get(revConnection);

					} else {

						tcpConnection = new TcpConnection();
						tcpConnection.source = connection.sourceIp;
						tcpConnection.destination = connection.destinationIp;
						tcpConnection.sport = connection.sourcePort;
						tcpConnection.dport = connection.destinationPort;

					}

					// Only Http Connections required for this task
					if ((connection.sourcePort == 80 || connection.destinationPort == 80)) {

						int tcpPayloadStart = i + ETHERNET_HEADER_LENGTH + ipHeaderLength + tcpHeaderLength;

						if (connection.destinationPort == 80) {

							for (int j = 0; j < tcpPayloadLength && tcpPayloadLength != 0; ++j) {

								tcpConnection.upstreamData.add(captureData[tcpPayloadStart + j]);

							}

							tcpConnection.upDataLength += tcpPayloadLength;

							TcpConnectionsTable.put(connection, tcpConnection);

						} else if (connection.sourcePort == 80) {

							for (int k = 0; k < tcpPayloadLength && tcpPayloadLength != 0; ++k) {

								tcpConnection.downstreamData.add(captureData[tcpPayloadStart + k]);
							}

							tcpConnection.downDataLength += tcpPayloadLength;

							TcpConnectionsTable.put(revConnection, tcpConnection);
						}

					}

				}
			}
			i += totalPacketLength + PACKET_HEADER_LENGTH;
		}
		for (Entry<ConnectionTuple, TcpConnection> entry : TcpConnectionsTable.entrySet()) {
			ConnectionTuple connection = entry.getKey();
			connection.upDataLength = entry.getValue().upDataLength;
			connection.downDataLength = entry.getValue().downDataLength;
			sortedTcpConnectionsTable.put(connection, entry.getValue());
		}

		for (Entry<ConnectionTuple, TcpConnection> entry : sortedTcpConnectionsTable.entrySet()) {

			System.out.print(entry.getKey().toString().substring(0, entry.getKey().toString().length()) + "\n");
		}

		OutputStream out = new DataOutputStream(System.out);

		try {
			for (Entry<ConnectionTuple, TcpConnection> entry : sortedTcpConnectionsTable.entrySet()) {

				List<Byte> b = entry.getValue().upstreamData;

				for (int i = 0; i < entry.getValue().upDataLength; i++) {

					out.write(b.get(i));
				}
				out.flush();

				b = entry.getValue().downstreamData;

				for (int i = 0; i < entry.getValue().downDataLength; i++) {

					out.write(b.get(i));
				}
				out.flush();
			}

			out.close();
		} catch (IOException e) {
			System.out.println("Error in Outputstream");
		}

	}

	static void task3(byte[] captureData, int captureSize) {

		Map<ConnectionTuple, TcpConnection> TcpConnectionsTable = new HashMap<ConnectionTuple, TcpConnection>();

		Map<Long, HttpConnection> httpConnectionReqTable = new HashMap<Long, HttpConnection>();
		Map<Long, HttpConnection> httpConnectionResTable = new HashMap<Long, HttpConnection>();

		// The Pcap file header is 24 bytes.
		// Packet headers are 16 bytes.
		// To count total number of packets need to count the number of packet
		// headers.
		// Ethernet header is 14 bytes
		// Upper layer protocol of ipv4 is in 9th byte of ethernet header

		// i in the loop points to the start of packet payload.
		for (int i = PCAP_HEADER_LENGTH + PACKET_HEADER_LENGTH; i < captureSize;) {

			long packetSequenceNumber;
			long acknowledgementNumber;
			long captureTime;
			long microOffset;

			// Converting 4 bytes of data into a single integer
			int totalPacketLength = Byte.toUnsignedInt(captureData[i - 1]);
			totalPacketLength <<= 8;
			totalPacketLength |= Byte.toUnsignedInt(captureData[i - 2]);
			totalPacketLength <<= 8;
			totalPacketLength |= Byte.toUnsignedInt(captureData[i - 3]);
			totalPacketLength <<= 8;
			totalPacketLength |= Byte.toUnsignedInt(captureData[i - 4]);

			// i+12 is specifies the length (if<1500) or type ethernet frame
			// header
			int frameType = Byte.toUnsignedInt(captureData[i + 12]);
			frameType <<= 8;
			frameType |= Byte.toUnsignedInt(captureData[i + 13]);

			if (frameType == 2048) { // ipv4 packet

				// i+ETHERNET_HEADER_LENGTH is the start of IP Packet
				int ipHeaderLength = Byte.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH]);
				// But only last 4 bits is the length
				ipHeaderLength &= 15;// Removes first 4 bits
				ipHeaderLength *= 4; // The length is specified as 32bit words

				int ipTotalLength = Byte.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + 2]);
				ipTotalLength <<= 8;
				ipTotalLength |= Byte.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + 3]);

				if (Byte.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + 9]) == 6) { // TCP
					// packet

					TcpConnection tcpConnection;
					ConnectionTuple connection = new ConnectionTuple();
					ConnectionTuple revConnection = new ConnectionTuple();

					// first 4 bytes of 12th byte of TCP header is data offset
					int tcpHeaderLength = Byte
							.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 12]);
					tcpHeaderLength >>= 4;
					tcpHeaderLength *= 4; // 32bit words to bytes

					int tcpPayloadLength = ipTotalLength - ipHeaderLength - tcpHeaderLength;

					IpAddress temp = new IpAddress();
					temp.firstByte = captureData[i + ETHERNET_HEADER_LENGTH + 12];
					temp.secondByte = captureData[i + ETHERNET_HEADER_LENGTH + 13];
					temp.thirdByte = captureData[i + ETHERNET_HEADER_LENGTH + 14];
					temp.fourthByte = captureData[i + ETHERNET_HEADER_LENGTH + 15];
					connection.sourceIp = temp;

					temp = new IpAddress();
					temp.firstByte = captureData[i + ETHERNET_HEADER_LENGTH + 16];
					temp.secondByte = captureData[i + ETHERNET_HEADER_LENGTH + 17];
					temp.thirdByte = captureData[i + ETHERNET_HEADER_LENGTH + 18];
					temp.fourthByte = captureData[i + ETHERNET_HEADER_LENGTH + 19];
					connection.destinationIp = temp;

					connection.sourcePort = Byte
							.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength]);
					connection.sourcePort <<= 8;
					connection.sourcePort |= Byte
							.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 1]);

					connection.destinationPort = Byte
							.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 2]);
					connection.destinationPort <<= 8;
					connection.destinationPort |= Byte
							.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 3]);

					revConnection.destinationIp = connection.sourceIp;
					revConnection.sourceIp = connection.destinationIp;
					revConnection.sourcePort = connection.destinationPort;
					revConnection.destinationPort = connection.sourcePort;

					if (TcpConnectionsTable.containsKey(connection)) {

						tcpConnection = TcpConnectionsTable.get(connection);

					} else if (TcpConnectionsTable.containsKey(revConnection)) {

						tcpConnection = TcpConnectionsTable.get(revConnection);

					} else {

						tcpConnection = new TcpConnection();
						tcpConnection.source = connection.sourceIp;
						tcpConnection.destination = connection.destinationIp;
						tcpConnection.sport = connection.sourcePort;
						tcpConnection.dport = connection.destinationPort;

					}

					// Only Http Connections required for this task
					if (connection.sourcePort == 80 || connection.destinationPort == 80) {

						packetSequenceNumber = Byte
								.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 4]);
						packetSequenceNumber <<= 8;
						packetSequenceNumber |= Byte
								.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 5]);
						packetSequenceNumber <<= 8;
						packetSequenceNumber |= Byte
								.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 6]);
						packetSequenceNumber <<= 8;
						packetSequenceNumber |= Byte
								.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 7]);

						acknowledgementNumber = Byte
								.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 8]);
						acknowledgementNumber <<= 8;
						acknowledgementNumber |= Byte
								.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 9]);
						acknowledgementNumber <<= 8;
						acknowledgementNumber |= Byte
								.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 10]);
						acknowledgementNumber <<= 8;
						acknowledgementNumber |= Byte
								.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 11]);

						// System.out.println("First time: " + (i - 12) + "\t" +
						// Byte.toUnsignedInt(captureData[i - 12]));

						microOffset = Byte.toUnsignedInt(captureData[i - 9]);
						microOffset <<= 8;
						microOffset |= Byte.toUnsignedInt(captureData[i - 10]);
						microOffset <<= 8;
						microOffset |= Byte.toUnsignedInt(captureData[i - 11]);
						microOffset <<= 8;
						microOffset |= Byte.toUnsignedInt(captureData[i - 12]);

						// System.out.println("Micro: " + microOffset);

						captureTime = Byte.toUnsignedInt(captureData[i - 13]);
						captureTime <<= 8;
						captureTime |= Byte.toUnsignedInt(captureData[i - 14]);
						captureTime <<= 8;
						captureTime |= Byte.toUnsignedInt(captureData[i - 15]);
						captureTime <<= 8;
						captureTime |= Byte.toUnsignedInt(captureData[i - 16]);

						int tcpPayloadStart = i + ETHERNET_HEADER_LENGTH + ipHeaderLength + tcpHeaderLength;

						Packet packet = new Packet();
						packet.sequenceNumber = packetSequenceNumber;
						packet.acknowledgementNumber = acknowledgementNumber;
						packet.captureTime = captureTime;
						packet.microOffset = microOffset;

						if (connection.destinationPort == 80) {

							for (int j = 0; j < tcpPayloadLength && tcpPayloadLength != 0; ++j) {

								packet.data.add(captureData[tcpPayloadStart + j]);

							}
							tcpConnection.upstreamPackets.add(packet);
							tcpConnection.upDataLength += tcpPayloadLength;

							TcpConnectionsTable.put(connection, tcpConnection);

						} else if (connection.sourcePort == 80) {

							for (int k = 0; k < tcpPayloadLength && tcpPayloadLength != 0; ++k) {

								packet.data.add(captureData[tcpPayloadStart + k]);

							}
							tcpConnection.downstreamPackets.add(packet);
							tcpConnection.downDataLength += tcpPayloadLength;

							TcpConnectionsTable.put(revConnection, tcpConnection);
						}

					}

				}
			}
			i += totalPacketLength + PACKET_HEADER_LENGTH;

		}

		for (Entry<ConnectionTuple, TcpConnection> entry : TcpConnectionsTable.entrySet()) {

			TcpConnection tcpConnection = entry.getValue();
			List<Packet> requestPackets = tcpConnection.upstreamPackets;
			List<Packet> responsePackets = tcpConnection.downstreamPackets;

			for (int i = 0; i < requestPackets.size(); ++i) {
				HttpConnection httpRequestConnection = new HttpConnection();
				List<Byte> requestData = requestPackets.get(i).data;
				boolean shouldStore = false;
				httpRequestConnection.acknowledgementNumber = requestPackets.get(i).acknowledgementNumber;
				httpRequestConnection.sequenceNumber = requestPackets.get(i).sequenceNumber;
				httpRequestConnection.receptionTime = String.valueOf(requestPackets.get(i).captureTime) + " "
						+ String.valueOf(requestPackets.get(i).microOffset);

				httpRequestConnection.captureTime = requestPackets.get(i).captureTime;
				httpRequestConnection.microOffset = requestPackets.get(i).microOffset;

				int prevChar = 0;
				int curChar = 0;
				StringBuilder singleLine = new StringBuilder();
				boolean isNewBlock = true;

				for (int j = 0; j < requestData.size(); ++j, prevChar = curChar) {

					curChar = requestData.get(j);
					singleLine.append((char) curChar);

					if (prevChar == 13 && curChar == 10 && singleLine.length() == 2) {
						isNewBlock = true;
						singleLine.delete(0, singleLine.length());
					} else if (prevChar == 13 && curChar == 10) {

						String firstWord = "noSpace";
						if (singleLine.indexOf(" ") != -1) {
							firstWord = singleLine.substring(0, singleLine.indexOf(" "));
						}

						if (isNewBlock) {

							if (firstWord.equalsIgnoreCase("HEAD") || firstWord.equalsIgnoreCase("GET")
									|| firstWord.equalsIgnoreCase("POST") || firstWord.equalsIgnoreCase("PUT")
									|| firstWord.equalsIgnoreCase("DELETE")) {

								int firstSpace = singleLine.indexOf(" ") + 1;
								// System.out
								// .println(singleLine.substring(firstSpace,
								// singleLine.indexOf(" ", firstSpace + 1)));

								httpRequestConnection.requestedUrl = singleLine.substring(firstSpace,
										singleLine.indexOf(" ", firstSpace + 1));
								shouldStore = true;
								// System.out.println(
								// (httpRequestConnection.sequenceNumber +
								// requestPackets.get(i).data.size()) + " "
								// + httpRequestConnection.requestedUrl);

							}

							isNewBlock = false;
						} else if (firstWord.equalsIgnoreCase("Host:")) {

							int firstSpace = singleLine.indexOf(" ") + 1;
							// System.out.println(singleLine.substring(firstSpace,
							// singleLine.length() - 2));

							httpRequestConnection.hostname = singleLine.substring(firstSpace, singleLine.length() - 2);

						}

						singleLine.delete(0, singleLine.length());
					}

				}
				// Storing the expected acknowledgement Number of response
				if (shouldStore)
					httpConnectionReqTable.put(httpRequestConnection.sequenceNumber + requestPackets.get(i).data.size(),
							httpRequestConnection);
			}

			long chunkedLength = 0L;
			long chunkCounter = 0L;
			boolean chunkCounterActive = false;
			long chunkKey = 0L;
			for (int i = 0; i < responsePackets.size(); ++i) {
				List<Byte> responseData = responsePackets.get(i).data;
				boolean shouldStore = false;
				boolean chunkedEncoding = false;
				long contentLength = 0L;

				HttpConnection httpResponseConnection = new HttpConnection();

				httpResponseConnection.acknowledgementNumber = responsePackets.get(i).acknowledgementNumber;
				httpResponseConnection.sequenceNumber = responsePackets.get(i).sequenceNumber;
				httpResponseConnection.receptionTime = responsePackets.get(i).captureTime + " "
						+ responsePackets.get(i).microOffset;

				httpResponseConnection.captureTime = responsePackets.get(i).captureTime;
				httpResponseConnection.microOffset = responsePackets.get(i).microOffset;

				int prevChar = 0;
				int curChar = 0;
				boolean isNewBlock = true;
				StringBuilder singleLine = new StringBuilder();

				for (int j = 0; j < responseData.size(); ++j, prevChar = curChar) {

					curChar = responseData.get(j);
					singleLine.append((char) curChar);

					if (prevChar == 13 && curChar == 10 && singleLine.length() == 2) {
						isNewBlock = true;
						// System.out.println(isNewBlock);
						singleLine.delete(0, singleLine.length());
					} else if (prevChar == 13 && curChar == 10) {

						String firstWord = "noSpace";
						if (singleLine.indexOf(" ") != -1) {
							firstWord = singleLine.substring(0, singleLine.indexOf(" "));
							// if (chunkedEncoding)
							// System.out.println("Chunk first word : " +
							// firstWord);
						}

						if (chunkCounterActive) {
							// -2 is to eliminate the \r\n in the end
							if (chunkCounter < -2) {
								String encodingValue = singleLine.substring(0, singleLine.length() - 2);
								// System.out.println("value is : " +
								// encodingValue);
								chunkCounter = Long.parseLong(encodingValue, 16);
								chunkedLength += chunkCounter;
								if (chunkCounter == 0) {
									// End of Chunk reached
									// System.out.println("Total Length " +
									// chunkedLength);
									HttpConnection temp = httpConnectionResTable.get(chunkKey);
									temp.responseBodyLength = chunkedLength;
									httpConnectionResTable.put(chunkKey, temp);

									chunkCounterActive = false;
								} else
									chunkCounterActive = true;

							}
						}
						if (firstWord.equalsIgnoreCase("HTTP/1.1")) {
							int firstSpace = singleLine.indexOf(" ") + 1;
							// System.out.print(httpResponseConnection.acknowledgementNumber
							// + " " + singleLine);
							httpResponseConnection.responseCode = Integer.parseInt(
									singleLine.substring(firstSpace, singleLine.indexOf(" ", firstSpace + 1)));

							shouldStore = true;

							// System.out.println(httpResponseConnection.acknowledgementNumber
							// + " "
							// + httpResponseConnection.responseCode);

						} else if (firstWord.equalsIgnoreCase("Content-Length:")) {
							int firstSpace = singleLine.indexOf(" ") + 1;
							contentLength = Long.parseLong(singleLine.substring(firstSpace, singleLine.length() - 2));

						} else if (firstWord.equalsIgnoreCase("Transfer-Encoding:")) {
							int firstSpace = singleLine.indexOf(" ") + 1;
							if (singleLine.substring(firstSpace, singleLine.length() - 2).equals("chunked")) {
								chunkedEncoding = true;

								// System.out.println("chunked: ");
							}

						} else if (isNewBlock && singleLine.indexOf(" ") == -1 && chunkedEncoding) {
							// This executes only at the start of chunk
							chunkKey = httpResponseConnection.acknowledgementNumber;
							String encodingValue = singleLine.substring(0, singleLine.length() - 2);
							chunkedLength = 0;
							// System.out
							// .println("value is : " + encodingValue + "\t" +
							// Long.parseLong(encodingValue, 16));
							chunkCounter = Long.parseLong(encodingValue, 16);
							chunkedLength += chunkCounter;
							chunkCounterActive = true;

						}
						isNewBlock = false;
						singleLine.delete(0, singleLine.length());
					}
					// this is to keep track of chunk
					if (chunkCounterActive)
						chunkCounter--;

				}
				if (shouldStore) {

					if (chunkedEncoding) {
						httpResponseConnection.responseBodyLength = chunkedLength;
					} else {
						httpResponseConnection.responseBodyLength = contentLength;
					}
					httpConnectionResTable.put(httpResponseConnection.acknowledgementNumber, httpResponseConnection);
				}
			}
			// httpConnectionTable.put(httpConnection, httpConnection);

		}

		// System.out.println(httpConnectionResTable.size() + "\t" +
		// httpConnectionReqTable.size());

		List<HttpConnection> outArray = new ArrayList<HttpConnection>();

		for (Entry<Long, HttpConnection> entry : httpConnectionReqTable.entrySet()) {

			HttpConnection httpConnection = entry.getValue();
			HttpConnection newOne = new HttpConnection();

			long seqNum = entry.getKey();

			if (httpConnectionResTable.containsKey(seqNum)) {

				// System.out.println(httpConnection.requestedUrl + " " +
				// httpConnection.hostname + " "
				// + httpConnectionResTable.get(seqNum).responseCode + " "
				// + httpConnectionResTable.get(seqNum).responseBodyLength);
				httpConnection.responseCode = httpConnectionResTable.get(seqNum).responseCode;
				httpConnection.responseBodyLength = httpConnectionResTable.get(seqNum).responseBodyLength;

				newOne.responseCode = httpConnection.responseCode;
				newOne.responseBodyLength = httpConnection.responseBodyLength;
				newOne.receptionTime = httpConnection.receptionTime;

				// if (outputTable.containsKey(httpConnection))
				// System.out.println("omg\t" + httpConnection.hostname);

				// outputTable.put(httpConnection, httpConnection);

				outArray.add(httpConnection);
			}

		}

		outArray.sort(HttpConnection.HttpConnectionComparator);

		for (HttpConnection httpConnection : outArray) {

			System.out.print(httpConnection.requestedUrl.toLowerCase() + " " + httpConnection.hostname.toLowerCase()
					+ " " + httpConnection.responseCode + " " + httpConnection.responseBodyLength + "\n");

		}

	}

	static void task4(byte[] captureData, int captureSize) {

		Map<ConnectionTuple, TcpConnection> TcpConnectionsTable = new HashMap<ConnectionTuple, TcpConnection>();

		Map<Long, HttpConnection> httpConnectionReqTable = new HashMap<Long, HttpConnection>();
		Map<Long, HttpConnection> httpConnectionResTable = new HashMap<Long, HttpConnection>();

		// The Pcap file header is 24 bytes.
		// Packet headers are 16 bytes.
		// To count total number of packets need to count the number of packet
		// headers.
		// Ethernet header is 14 bytes
		// Upper layer protocol of ipv4 is in 9th byte of ethernet header

		// i in the loop points to the start of packet payload.
		for (int i = PCAP_HEADER_LENGTH + PACKET_HEADER_LENGTH; i < captureSize;) {

			long packetSequenceNumber;
			long acknowledgementNumber;
			long captureTime;
			long microOffset;

			// Converting 4 bytes of data into a single integer
			int totalPacketLength = Byte.toUnsignedInt(captureData[i - 1]);
			totalPacketLength <<= 8;
			totalPacketLength |= Byte.toUnsignedInt(captureData[i - 2]);
			totalPacketLength <<= 8;
			totalPacketLength |= Byte.toUnsignedInt(captureData[i - 3]);
			totalPacketLength <<= 8;
			totalPacketLength |= Byte.toUnsignedInt(captureData[i - 4]);

			// i+12 is specifies the length (if<1500) or type ethernet frame
			// header
			int frameType = Byte.toUnsignedInt(captureData[i + 12]);
			frameType <<= 8;
			frameType |= Byte.toUnsignedInt(captureData[i + 13]);

			if (frameType == 2048) { // ipv4 packet

				// i+ETHERNET_HEADER_LENGTH is the start of IP Packet
				int ipHeaderLength = Byte.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH]);
				// But only last 4 bits is the length
				ipHeaderLength &= 15;// Removes first 4 bits
				ipHeaderLength *= 4; // The length is specified as 32bit words

				int ipTotalLength = Byte.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + 2]);
				ipTotalLength <<= 8;
				ipTotalLength |= Byte.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + 3]);

				if (Byte.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + 9]) == 6) { // TCP
					// packet

					TcpConnection tcpConnection;
					ConnectionTuple connection = new ConnectionTuple();
					ConnectionTuple revConnection = new ConnectionTuple();

					// first 4 bytes of 12th byte of TCP header is data offset
					int tcpHeaderLength = Byte
							.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 12]);
					tcpHeaderLength >>= 4;
					tcpHeaderLength *= 4; // 32bit words to bytes

					int tcpPayloadLength = ipTotalLength - ipHeaderLength - tcpHeaderLength;

					IpAddress temp = new IpAddress();
					temp.firstByte = captureData[i + ETHERNET_HEADER_LENGTH + 12];
					temp.secondByte = captureData[i + ETHERNET_HEADER_LENGTH + 13];
					temp.thirdByte = captureData[i + ETHERNET_HEADER_LENGTH + 14];
					temp.fourthByte = captureData[i + ETHERNET_HEADER_LENGTH + 15];
					connection.sourceIp = temp;

					temp = new IpAddress();
					temp.firstByte = captureData[i + ETHERNET_HEADER_LENGTH + 16];
					temp.secondByte = captureData[i + ETHERNET_HEADER_LENGTH + 17];
					temp.thirdByte = captureData[i + ETHERNET_HEADER_LENGTH + 18];
					temp.fourthByte = captureData[i + ETHERNET_HEADER_LENGTH + 19];
					connection.destinationIp = temp;

					connection.sourcePort = Byte
							.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength]);
					connection.sourcePort <<= 8;
					connection.sourcePort |= Byte
							.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 1]);

					connection.destinationPort = Byte
							.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 2]);
					connection.destinationPort <<= 8;
					connection.destinationPort |= Byte
							.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 3]);

					revConnection.destinationIp = connection.sourceIp;
					revConnection.sourceIp = connection.destinationIp;
					revConnection.sourcePort = connection.destinationPort;
					revConnection.destinationPort = connection.sourcePort;

					if (TcpConnectionsTable.containsKey(connection)) {

						tcpConnection = TcpConnectionsTable.get(connection);

					} else if (TcpConnectionsTable.containsKey(revConnection)) {

						tcpConnection = TcpConnectionsTable.get(revConnection);

					} else {

						tcpConnection = new TcpConnection();
						tcpConnection.source = connection.sourceIp;
						tcpConnection.destination = connection.destinationIp;
						tcpConnection.sport = connection.sourcePort;
						tcpConnection.dport = connection.destinationPort;

					}

					// Only Http Connections required for this task
					if (connection.sourcePort == 80 || connection.destinationPort == 80) {

						packetSequenceNumber = Byte
								.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 4]);
						packetSequenceNumber <<= 8;
						packetSequenceNumber |= Byte
								.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 5]);
						packetSequenceNumber <<= 8;
						packetSequenceNumber |= Byte
								.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 6]);
						packetSequenceNumber <<= 8;
						packetSequenceNumber |= Byte
								.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 7]);

						acknowledgementNumber = Byte
								.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 8]);
						acknowledgementNumber <<= 8;
						acknowledgementNumber |= Byte
								.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 9]);
						acknowledgementNumber <<= 8;
						acknowledgementNumber |= Byte
								.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 10]);
						acknowledgementNumber <<= 8;
						acknowledgementNumber |= Byte
								.toUnsignedInt(captureData[i + ETHERNET_HEADER_LENGTH + ipHeaderLength + 11]);

						// System.out.println("First time: " + (i - 12) + "\t" +
						// Byte.toUnsignedInt(captureData[i - 12]));

						microOffset = Byte.toUnsignedInt(captureData[i - 9]);
						microOffset <<= 8;
						microOffset |= Byte.toUnsignedInt(captureData[i - 10]);
						microOffset <<= 8;
						microOffset |= Byte.toUnsignedInt(captureData[i - 11]);
						microOffset <<= 8;
						microOffset |= Byte.toUnsignedInt(captureData[i - 12]);

						// System.out.println("Micro: " + microOffset);

						captureTime = Byte.toUnsignedInt(captureData[i - 13]);
						captureTime <<= 8;
						captureTime |= Byte.toUnsignedInt(captureData[i - 14]);
						captureTime <<= 8;
						captureTime |= Byte.toUnsignedInt(captureData[i - 15]);
						captureTime <<= 8;
						captureTime |= Byte.toUnsignedInt(captureData[i - 16]);

						int tcpPayloadStart = i + ETHERNET_HEADER_LENGTH + ipHeaderLength + tcpHeaderLength;

						Packet packet = new Packet();
						packet.sequenceNumber = packetSequenceNumber;
						packet.acknowledgementNumber = acknowledgementNumber;
						packet.captureTime = captureTime;
						packet.microOffset = microOffset;

						if (connection.destinationPort == 80) {

							for (int j = 0; j < tcpPayloadLength && tcpPayloadLength != 0; ++j) {

								packet.data.add(captureData[tcpPayloadStart + j]);

							}
							tcpConnection.upstreamPackets.add(packet);
							tcpConnection.upDataLength += tcpPayloadLength;

							TcpConnectionsTable.put(connection, tcpConnection);

						} else if (connection.sourcePort == 80) {

							for (int k = 0; k < tcpPayloadLength && tcpPayloadLength != 0; ++k) {

								packet.data.add(captureData[tcpPayloadStart + k]);

							}
							tcpConnection.downstreamPackets.add(packet);
							tcpConnection.downDataLength += tcpPayloadLength;

							TcpConnectionsTable.put(revConnection, tcpConnection);
						}

					}

				}
			}
			i += totalPacketLength + PACKET_HEADER_LENGTH;

		}

		for (Entry<ConnectionTuple, TcpConnection> entry : TcpConnectionsTable.entrySet()) {

			TcpConnection tcpConnection = entry.getValue();
			List<Packet> requestPackets = tcpConnection.upstreamPackets;
			List<Packet> responsePackets = tcpConnection.downstreamPackets;

			for (int i = 0; i < requestPackets.size(); ++i) {
				HttpConnection httpRequestConnection = new HttpConnection();
				List<Byte> requestData = requestPackets.get(i).data;
				boolean shouldStore = false;
				httpRequestConnection.acknowledgementNumber = requestPackets.get(i).acknowledgementNumber;
				httpRequestConnection.sequenceNumber = requestPackets.get(i).sequenceNumber;
				httpRequestConnection.receptionTime = String.valueOf(requestPackets.get(i).captureTime) + " "
						+ String.valueOf(requestPackets.get(i).microOffset);

				httpRequestConnection.captureTime = requestPackets.get(i).captureTime;
				httpRequestConnection.microOffset = requestPackets.get(i).microOffset;

				int prevChar = 0;
				int curChar = 0;
				StringBuilder singleLine = new StringBuilder();
				boolean isNewBlock = true;

				for (int j = 0; j < requestData.size(); ++j, prevChar = curChar) {

					curChar = requestData.get(j);
					singleLine.append((char) curChar);

					if (prevChar == 13 && curChar == 10 && singleLine.length() == 2) {
						isNewBlock = true;
						singleLine.delete(0, singleLine.length());
					} else if (prevChar == 13 && curChar == 10) {

						String firstWord = "noSpace";
						if (singleLine.indexOf(" ") != -1) {
							firstWord = singleLine.substring(0, singleLine.indexOf(" "));
						}

						if (isNewBlock) {

							if (firstWord.equalsIgnoreCase("HEAD") || firstWord.equalsIgnoreCase("GET")
									|| firstWord.equalsIgnoreCase("POST") || firstWord.equalsIgnoreCase("PUT")
									|| firstWord.equalsIgnoreCase("DELETE")) {

								int firstSpace = singleLine.indexOf(" ") + 1;
								// System.out
								// .println(singleLine.substring(firstSpace,
								// singleLine.indexOf(" ", firstSpace + 1)));

								httpRequestConnection.requestedUrl = singleLine.substring(firstSpace,
										singleLine.indexOf(" ", firstSpace + 1));

								String extension1 = " ";
								String extension2 = " ";

								if (httpRequestConnection.requestedUrl.length() > 5) {
									extension1 = httpRequestConnection.requestedUrl
											.substring(httpRequestConnection.requestedUrl.length() - 5);
								}
								if (httpRequestConnection.requestedUrl.length() > 4) {
									extension2 = httpRequestConnection.requestedUrl
											.substring(httpRequestConnection.requestedUrl.length() - 4);
								}
								// Only image formats required
								if (extension1.equalsIgnoreCase(".jpeg") || extension1.equalsIgnoreCase(".webp")
										|| extension2.equalsIgnoreCase(".jpg") || extension2.equalsIgnoreCase(".png")
										|| extension2.equalsIgnoreCase(".gif"))
									shouldStore = true;
								// System.out.println(
								// (httpRequestConnection.sequenceNumber +
								// requestPackets.get(i).data.size()) + " "
								// + httpRequestConnection.requestedUrl);

							}

							isNewBlock = false;
						} else if (firstWord.equalsIgnoreCase("Host:")) {

							int firstSpace = singleLine.indexOf(" ") + 1;
							// System.out.println(singleLine.substring(firstSpace,
							// singleLine.length() - 2));

							httpRequestConnection.hostname = singleLine.substring(firstSpace, singleLine.length() - 2);

						}

						singleLine.delete(0, singleLine.length());
					}

				}
				// Storing the expected acknowledgement Number of response
				if (shouldStore)
					httpConnectionReqTable.put(httpRequestConnection.sequenceNumber + requestPackets.get(i).data.size(),
							httpRequestConnection);
			}

			long chunkedLength = 0L;
			long chunkCounter = 0L;
			boolean chunkCounterActive = false;
			long chunkKey = 0L;
			// This is for contentLength
			boolean headerEndWait = false;
			boolean contentDataActive = false;
			long contentKey = 0L;
			long contentCounter = 0L;
			long contentDataLength = 0L;
			int contentResponseCode = 0;
			List<Byte> contentData = new ArrayList<Byte>();

			for (int i = 0; i < responsePackets.size(); ++i) {
				List<Byte> responseData = responsePackets.get(i).data;
				boolean shouldStore = false;
				boolean chunkedEncoding = false;
				long contentLength = 0L;

				HttpConnection httpResponseConnection = new HttpConnection();

				httpResponseConnection.acknowledgementNumber = responsePackets.get(i).acknowledgementNumber;
				httpResponseConnection.sequenceNumber = responsePackets.get(i).sequenceNumber;
				httpResponseConnection.receptionTime = responsePackets.get(i).captureTime + " "
						+ responsePackets.get(i).microOffset;

				httpResponseConnection.captureTime = responsePackets.get(i).captureTime;
				httpResponseConnection.microOffset = responsePackets.get(i).microOffset;

				int prevChar = 0;
				int curChar = 0;
				boolean isNewBlock = true;
				StringBuilder singleLine = new StringBuilder();
				List<Byte> singleLineBytes = new ArrayList<Byte>();

				for (int j = 0; j < responseData.size(); ++j, prevChar = curChar) {

					curChar = responseData.get(j);
					singleLineBytes.add(responseData.get(j));
					singleLine.append((char) curChar);

					if (contentDataActive) {

						contentData.add(responseData.get(j));
						contentCounter += 1;
						// End of content data
						if (contentCounter >= contentDataLength) {

							HttpConnection temp = new HttpConnection();
							temp.responseBodyLength = contentDataLength;
							temp.responseData = contentData;

							temp.responseCode = contentResponseCode;
							httpConnectionResTable.put(contentKey, temp);

							contentCounter = 0L;
							contentDataLength = 0L;
							contentResponseCode = 0;
							contentData = new ArrayList<Byte>();

							contentDataActive = false;
						}

					}

					if (prevChar == 13 && curChar == 10 && singleLine.length() == 2) {
						isNewBlock = true;
						// System.out.println(isNewBlock);
						singleLine.delete(0, singleLine.length());
					} else if (prevChar == 13 && curChar == 10) {

						if (headerEndWait && isNewBlock) {
							contentDataActive = true;

							// contentData.addAll(singleLineBytes);
							// contentCounter += singleLineBytes.size();
							contentData.clear();

							contentKey = httpResponseConnection.acknowledgementNumber;
							// header has been crossed
							headerEndWait = false;
						}
						String firstWord = "noSpace";
						if (singleLine.indexOf(" ") != -1) {
							firstWord = singleLine.substring(0, singleLine.indexOf(" "));
							// if (chunkedEncoding)
							// System.out.println("Chunk first word : " +
							// firstWord);
						}

						if (chunkCounterActive) {
							// -2 is to eliminate the \r\n in the end

							if (chunkCounter < -2) {
								String encodingValue = singleLine.substring(0, singleLine.length() - 2);
								// System.out.println("value is : " +
								// encodingValue);
								chunkCounter = Long.parseLong(encodingValue, 16);
								chunkedLength += chunkCounter;
								if (chunkCounter == 0) {
									// End of Chunk reached
									// System.out.println("Total Length " +
									// chunkedLength);
									HttpConnection temp = httpConnectionResTable.get(chunkKey);
									temp.responseBodyLength = chunkedLength;
									httpConnectionResTable.put(chunkKey, temp);

									chunkCounterActive = false;
								} else
									chunkCounterActive = true;

							}
						}
						if (firstWord.equalsIgnoreCase("HTTP/1.1")) {
							int firstSpace = singleLine.indexOf(" ") + 1;
							// System.out.print(httpResponseConnection.acknowledgementNumber
							// + " " + singleLine);
							httpResponseConnection.responseCode = Integer.parseInt(
									singleLine.substring(firstSpace, singleLine.indexOf(" ", firstSpace + 1)));

							shouldStore = true;

							// System.out.println(httpResponseConnection.acknowledgementNumber
							// + " "
							// + httpResponseConnection.responseCode);

						} else if (firstWord.equalsIgnoreCase("Content-Length:")) {
							int firstSpace = singleLine.indexOf(" ") + 1;
							contentLength = Long.parseLong(singleLine.substring(firstSpace, singleLine.length() - 2));
							headerEndWait = true;
							contentDataLength = contentLength;
							contentKey = httpResponseConnection.acknowledgementNumber;
							contentResponseCode = httpResponseConnection.responseCode;

							// System.out.println(
							// "Response size : " + responseData.size() +
							// "\tContent-Length : " + contentLength);

						} else if (firstWord.equalsIgnoreCase("Transfer-Encoding:")) {
							int firstSpace = singleLine.indexOf(" ") + 1;
							if (singleLine.substring(firstSpace, singleLine.length() - 2).equals("chunked")) {
								chunkedEncoding = true;

								// System.out.println("chunked: ");
							}

						} else if (isNewBlock && singleLine.indexOf(" ") == -1 && chunkedEncoding) {
							// This executes only at the start of chunk
							chunkKey = httpResponseConnection.acknowledgementNumber;
							String encodingValue = singleLine.substring(0, singleLine.length() - 2);
							chunkedLength = 0;
							// System.out
							// .println("value is : " + encodingValue + "\t" +
							// Long.parseLong(encodingValue, 16));
							chunkCounter = Long.parseLong(encodingValue, 16);
							chunkedLength += chunkCounter;
							chunkCounterActive = true;

						}
						isNewBlock = false;
						singleLine.delete(0, singleLine.length());
					}
					// this is to keep track of chunk
					if (chunkCounterActive)
						chunkCounter--;

				}
				if (shouldStore) {

					if (chunkedEncoding) {
						httpResponseConnection.responseBodyLength = chunkedLength;
					} else {
						httpResponseConnection.responseBodyLength = contentLength;
					}
					httpConnectionResTable.put(httpResponseConnection.acknowledgementNumber, httpResponseConnection);
				}
			}

		}

		List<HttpConnection> outArray = new ArrayList<HttpConnection>();

		for (Entry<Long, HttpConnection> entry : httpConnectionReqTable.entrySet()) {

			HttpConnection httpConnection = entry.getValue();

			long seqNum = entry.getKey();

			if (httpConnectionResTable.containsKey(seqNum)) {

				httpConnection.responseCode = httpConnectionResTable.get(seqNum).responseCode;
				httpConnection.responseBodyLength = httpConnectionResTable.get(seqNum).responseBodyLength;
				httpConnection.responseData = httpConnectionResTable.get(seqNum).responseData;

				outArray.add(httpConnection);
			}

		}

		outArray.sort(HttpConnection.HttpConnectionComparator);

		OutputStream out = new DataOutputStream(System.out);
		try {
			for (HttpConnection httpConnection : outArray) {
				// System.out.println(httpConnection.responseData.size());

				for (int i = 0; i < httpConnection.responseData.size(); ++i) {
					out.write(httpConnection.responseData.get(i));
				}
				out.flush();
				out.close();
			}
		} catch (IOException e) {
			System.out.println("I/O exception");
		}
	}

	public static void main(String[] args) throws IOException {

		byte[] captureData = new byte[MAX_CAPTURE_SIZE];
		int captureSize = 0;
		captureSize = input(captureData);

		for (String s : args) {
			if (Integer.parseInt(s) == 1) { // Task 1
				task1(captureData, captureSize);
			}

			if (Integer.parseInt(s) == 2) { // Task 2
				task2(captureData, captureSize);
			}

			if (Integer.parseInt(s) == 3) { // Task 3
				task3(captureData, captureSize);
			}

			if (Integer.parseInt(s) == 4) { // Task 4
				task4(captureData, captureSize);
			}
		}
	}

}
