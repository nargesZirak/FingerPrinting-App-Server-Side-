import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import jpcap.JpcapCaptor;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;


public class UserFingerprint implements PacketReceiver {

	public static boolean areSomeUsers;
	public static Map<String, UserInformation> identifiedUsers;	
	
	public static final int WINttl = 128;
	public static final int LINUXttl = 64;
	public static final int UNIXttl = 255;
	public static int [] TTLVALUES;
	public static PrintWriter pw; 
	public static int global=0;
	
	
	
	public static void main(String[] args) throws NumberFormatException, IOException
	{
		TTLVALUES = new int []{WINttl, LINUXttl, UNIXttl};
		
		//Path to the Log file
		pw = new PrintWriter("C:\\Install\\cpsc626\\log1.txt");
		pw.println("IP-address"+ "\t"+ "Source port" + "\t" + "TTL" + "\t" + "User Agent");
		areSomeUsers = false;
		identifiedUsers = new HashMap<String, UserInformation>();
				
		
		jpcap.NetworkInterface[] devices = JpcapCaptor.getDeviceList();
		for (int i=0; i< devices.length; i++)
		{
			System.out.println(i +" "+ devices[i].description);
		}
		
		JpcapCaptor jpcap = JpcapCaptor.openDevice(devices[1], 65535, false, 20);		
		
		while (true)
		{
			jpcap.processPacket(-1, new UserFingerprint());	
			if (global == 1000)
			{
				pw.close();
			}
			global++;
		}	
	}	
	
	@Override
	public void receivePacket(Packet packet) {
		
		try {
			//packet is ignored if it is not TCP packet
			TCPPacket tcpPac = (TCPPacket) packet;			
			packetParser(packet);
		} catch (ClassCastException e) {
			
		}		
	}
	
	public void packetParser(Packet packet)
	{
		
		String packetData = new String(packet.data);
		System.out.println(packetData);
		TCPPacket tcpPac = (TCPPacket) packet;
		int dest_port_in_packet = tcpPac.dst_port;
		int source_port_in_packet = tcpPac.src_port;
		String sourceIP= tcpPac.src_ip.toString();
		//pw.print(sourceIP+"\t");
		
		//String pac = packet.toString();
		if (dest_port_in_packet == 80)
		{
			
			if (areSomeUsers == false)
			{
				
				Integer portRange = getPortRange(source_port_in_packet);				
				String ipAndPortRange  = sourceIP+";"+ portRange.toString();
				
				UserInformation uinfo = new UserInformation();
				//======================  adding source port ================
				
				uinfo.source_port = source_port_in_packet;
				//System.out.println("here 2");
				//======================  adding ttl=========================
				
				int ttl =tcpPac.hop_limit;
				int identifiedTTL = findClosestValue(ttl);
				uinfo.ttl = identifiedTTL;
				//======================  adding WindowSize=========================
				
				int windowSize = tcpPac.window;
				uinfo.windowSize = windowSize;
				
				//======================  adding UserAgent=========================
//				String packetData = new String(packet.data);
				int startForUA = packetData.indexOf("User-Agent:");
				System.out.println("start for UA" + startForUA);
				int endForUA = packetData.indexOf("Referer");
				System.out.println("end for UA" + endForUA);
				if (startForUA!=-1 && endForUA!=-1 )
				{
					
					String userAgent = packetData.substring(startForUA, endForUA);
					uinfo.userAgent = userAgent;
					//System.out.println("here");
					pw.print(sourceIP+"\t");
					pw.print(source_port_in_packet+"\t");
					pw.print(identifiedTTL+"\t");
					pw.print(windowSize+ "\t");
					pw.print(userAgent);
					pw.println();
					identifiedUsers.put(ipAndPortRange, uinfo);					
					areSomeUsers = true;
					
				}				
			}
			
			else
			{
				Integer portRange = getPortRange(source_port_in_packet);				
				String ipAndPortRange  = sourceIP+";"+ portRange.toString();
				
				if (!identifiedUsers.containsKey(ipAndPortRange));
				{
//					String packetData = new String(packet.data);
					int startForUA = packetData.indexOf("User-Agent:");
					int endForUA = packetData.indexOf("Referer");
					if (startForUA!=-1 && endForUA!=-1 )
					{
						String userAgent = packetData.substring(startForUA, endForUA);
						
						boolean existUA= false;
						for (UserInformation values : identifiedUsers.values())
						{
							if (userAgent.equals(values.userAgent))
							{
								existUA= true;
							}							
						}
						if (!existUA)
						{
							UserInformation uinronew = new UserInformation();
							uinronew.source_port = source_port_in_packet;
							int ttl =tcpPac.hop_limit;
							int identifiedTTL = findClosestValue(ttl);
							uinronew.ttl = identifiedTTL;
							int windowSize = tcpPac.window;
							uinronew.windowSize = windowSize;
							
							pw.print(sourceIP+"\t");
							pw.print(source_port_in_packet+"\t");
							pw.print(identifiedTTL+"\t");
							
							pw.print(windowSize+ "\t");
							uinronew.userAgent = userAgent;
							pw.print(userAgent);
							pw.println();
							identifiedUsers.put(ipAndPortRange, uinronew);
						}
					} 
				}				
			}		
					
		}		
		
	}
	
	
	public int findClosestValue(int ttl)
	{
		int nearest = -1;
		int bestDistanceFoundYet = 0;
		// We iterate on the array...
		for (int i = 0; i < TTLVALUES.length; i++) {
		  // if we found the desired number, we return it.
		  if (TTLVALUES[i] == ttl) {
		    return TTLVALUES[i];
		  } else {
		    // else, we consider the difference between the desired number and the current number in the array.
		    int d = Math.abs(ttl - TTLVALUES[i]);
		    if (d < bestDistanceFoundYet) {
		      // For the moment, this value is the nearest to the desired number...
		      nearest = TTLVALUES[i];
		    }
		  }
		}
		return nearest;
		
	}
		
	
	public Integer getPortRange(int port)
	{
		Integer range  = new Integer((port -1036)/20) ; 
		return range;
	}

}

