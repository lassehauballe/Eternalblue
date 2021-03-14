using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Eternalblue
{
    class Program
    {

        private static byte[] negotiate_proto_request()
        {

            byte[] pkt = {0x00};             // Message_Type
            pkt += 0x00,0x00,0x54;       // Length
            kh
                asdasd;


            $pkt += 0xFF,0x53,0x4D,0x42 // server_component: .SMB
            $pkt += 0x72             // smb_command: Negotiate Protocol
            $pkt += 0x00,0x00,0x00,0x00 // nt_status
            $pkt += 0x18             // flags
            $pkt +=  0x01,0x28         // flags2
            $pkt += 0x00,0x00         // process_id_high
            $pkt += 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 // signature
            $pkt += 0x00,0x00         // reserved
            $pkt += 0x00,0x00         // tree_id
            $pkt += 0x2F,0x4B         // process_id
            $pkt += 0x00,0x00         // user_id
            $pkt += 0xC5,0x5E           // multiplex_id

            $pkt += 0x00             // word_count
            $pkt += 0x31,0x00         // byte_count

            //Requested Dialects
            $pkt += 0x02             // dialet_buffer_format
            $pkt += 0x4C,0x41,0x4E,0x4D,0x41,0x4E,0x31,0x2E,0x30,0x00  // dialet_name: LANMAN1.0

            $pkt += 0x02             // dialet_buffer_format
            $pkt += 0x4C,0x4D,0x31,0x2E,0x32,0x58,0x30,0x30,0x32,0x00  // dialet_name: LM1.2X002

            $pkt += 0x02             # dialet_buffer_format
            $pkt += 0x4E,0x54,0x20,0x4C,0x41,0x4E,0x4D,0x41,0x4E,0x20,0x31,0x2E,0x30,0x00 # dialet_name3: NT LANMAN 1.0

            $pkt += 0x02             # dialet_buffer_format
            $pkt += 0x4E,0x54,0x20,0x4C,0x4D,0x20,0x30,0x2E,0x31,0x32,0x00   # dialet_name4: NT LM 0.12

            return $pkt
}

        static string Client_Negotiate(Socket sock)
        {
            
            return "";
        }


        static void Main(string[] args)
        {
            string ip = "192.168.141.210";
            int port = 445;

            TcpClient client = new TcpClient(ip, port);
            Socket sock = client.Client;




        }
    }
}
