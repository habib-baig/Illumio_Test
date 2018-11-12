using namespace std;
class record{
public:
  int startport;
  int endport;
  string ipstart;
  string ipend;
};


class Firewall{
  private:
    vector<record> inboundUdp;
    vector<record> outboundUdp;
    vector<record> outboundTcp;
    vector<record> inboundTcp;

  public:
    Firewall(string path);
    void push_record(string &s);
    bool accept_packet(string dir, string protocol, int port, string ipaddress);
    bool search(vector<record> &records, int port, string ipaddress);
    bool binarySearch(vector<record> &records, int port, string ipaddress);
    void printrecords(vector<record> &records);
    void printallowedrules();
    };
