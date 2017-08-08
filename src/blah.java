import java.io.IOException;
import java.net.InetAddress;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.packet.EthernetPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.TCPPacket;


public class blah {
	public static void main(String [] args) throws IOException
	{		
		jpcap.NetworkInterface[] devices = JpcapCaptor.getDeviceList();
		for (int i=0; i< devices.length; i++)
		{
			System.out.println(i + " "+ devices[i].name);
		}
		
		JpcapSender sender = JpcapSender.openDevice(devices[1]);
		//IPPacket someIPpacket = new IPPacket();
		
		
		TCPPacket somePacket=new TCPPacket(5000,80,56,78,false,false,false,false,true,true,true,true,10,10);
		
		somePacket.setIPv4Parameter(0, false, false, false, 0, false, false, false, 0, 101, 10, IPPacket.IPPROTO_IP, InetAddress.getByName("192.168.173.1"), InetAddress.getByName("192.168.173.100"));
		somePacket.data="blah".getBytes();
		
		EthernetPacket ether = new EthernetPacket();
		ether.frametype= EthernetPacket.ETHERTYPE_IP;
		
		String source_mac="74:d0:2b:3c:20:3f";
		String destination_mac="08:00:27:81:99:ae";		
		
		ether.src_mac = macConverter(source_mac);
		ether.dst_mac = macConverter(destination_mac);		
		somePacket.datalink=ether;
		
		
		sender.sendPacket(somePacket);
		
		
		
		System.out.println("sent packet");
	
		
	}
	
	
	public static byte[] macConverter(String mac)
	{
		String[] macAddressParts = mac.split(":");

		// convert hex string to byte values
		byte[] macAddressBytes = new byte[6];
		for(int i=0; i<6; i++)
		{
		    Integer hex = Integer.parseInt(macAddressParts[i], 16);
		    macAddressBytes[i] = hex.byteValue();
		}
		return macAddressBytes;
	}
	

}
