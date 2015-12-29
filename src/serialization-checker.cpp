#include <tins/tins.h>
#include <iostream>
#include <algorithm>
#include <string>
#include <memory>
#include <functional>

using namespace Tins;
using namespace std;

class Checker {
public:
    Checker(const std::string& output_file) : 
    writer(output_file, DataLinkType<EthernetII>()), packets_written(0) {

    }

    void run(BaseSniffer& sniffer) {
        sniffer.sniff_loop(bind(&Checker::callback, this, placeholders::_1));
    }

private:
    bool callback(PDU& pdu) {
        RawPDU& raw = pdu.rfind_pdu<RawPDU>();
        auto& buffer = raw.payload();
        if (buffer.size() >= 60) {
            try {
                EthernetII eth(buffer.data(), buffer.size());
                const PDU* next = eth.inner_pdu();
                const ICMP* icmp = eth.find_pdu<ICMP>();
                const RawPDU* inner_raw = eth.find_pdu<RawPDU>();
                if (!icmp || !inner_raw || icmp->length() == 0 || inner_raw->size() == icmp->length() * 4) {
                    if (inner_raw && icmp && inner_raw->size() > 128 && icmp->length() == 0) {
                        return true;
                    }
                    auto serialized = eth.serialize();
                    if (next->size() < 46) {
                        auto start_iter = buffer.begin() + 14 + next->size();
                        fill(start_iter, buffer.end(), 0);
                    }
                    if (buffer != serialized) {
                        cout << "Storing packet since serialization differs" << endl;
                        save_packet(pdu);
                    }
                }
            }
            catch (exception& ex) {
                cout << "Storing packet due to exception when parsing: " << ex.what() << endl;
                save_packet(pdu);
            }
        }
        return packets_written < 1;
    }

    void save_packet(PDU& pdu) {
        writer.write(pdu);
        packets_written++;
    }

    PacketWriter writer;
    int packets_written;
};

int main(int argc, char *argv[]) {
    if (argc != 2) {
        cout << "Usage: " << argv[0] << " <interface | pcap-file>" << endl;
        return 1;
    }

    unique_ptr<BaseSniffer> sniffer;
    try {
        // Check if this is a network interface
        NetworkInterface iface(argv[1]);
        auto info = iface.info();
        cout << "Capturing on " << argv[1] << " (" << info.ip_addr << ")\n";

        SnifferConfiguration config;
        config.set_promisc_mode(true);
        sniffer.reset(new Sniffer(argv[1], config));
    }
    catch (exception&) {
        // If it isnt' a network interface, then it might be a path
        try {
            sniffer.reset(new FileSniffer(argv[1]));
            cout << "Reading from file " << argv[1] << endl;
        }
        catch (exception& ex) {
            cout << "Failed to read pcap file: " << ex.what() << endl;
            return 1;
        }
    }

    Checker checker("/tmp/serialization-checker.pcap");
    sniffer->set_extract_raw_pdus(true);
    checker.run(*sniffer);
}
