#include <tins/tins.h>
#include <iostream>
#include <string>
#include <functional>

using namespace Tins;
using namespace std;

class Differ {
public:
    Differ(const std::string& output_file, int number) : 
    packet_number(number), packets_seen(0) {

    }

    void run(BaseSniffer& sniffer) {
        sniffer.sniff_loop(bind(&Differ::callback, this, placeholders::_1));
    }
private:
    bool callback(PDU& pdu) {
        if (packet_number == packets_seen) {
            const RawPDU& raw = pdu.rfind_pdu<RawPDU>();
            const auto& buffer = raw.payload();
            try {
                EthernetII eth(buffer.data(), buffer.size());
                auto serialized = eth.serialize();
                if (buffer != serialized) {
                    PacketWriter writer(output_file, DataLinkType<EthernetII>());
                    writer.write(pdu);
                    writer.write(eth);
                    return false;
                }
                else {
                    cout << "Serialization is the same as original packet!\n";
                }
            }
            catch (exception& ex) {
                cout << "Exception when parsing: " << ex.what() << endl;
            }
        }
        packets_seen++;
        return true;
    }

    std::string output_file;
    int packet_number;
    int packets_seen;
};



int main(int argc, char *argv[]) {
    if (argc != 3) {
        cout << "Usage: " << argv[0] << " <file> <packet number>" << endl;
        cout << endl;
        cout << "Packet number should be 0-index based" << endl;
        return 1;
    }
    try {
        int packet_number = stoi(argv[2]);
        FileSniffer sniffer(argv[1]);
        sniffer.set_extract_raw_pdus(true);
        
        cout << "Reading from file " << argv[1] << endl;
        Differ differ("/tmp/serialization-diff.pcap", packet_number);
        differ.run(sniffer);
    }
    catch (exception& ex) {
        cout << "Error: " << ex.what() << endl;
    }
}
