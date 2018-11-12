using namespace std;
class rule{
public:
  int startport;
  int endport;
  string ipstart;
  string ipend;
};


class Firewall{
  private:
    vector<rule> inboundUdp;
    vector<rule> outboundUdp;
    vector<rule> outboundTcp;
    vector<rule> inboundTcp;

  public:
    Firewall(string path);
    void push_rule(string &s);
    bool accept_packet(string dir, string protocol, int port, string ipaddress);
    bool search(vector<rule> &rules, int port, string ipaddress);
    bool binarySearch(vector<rule> &rules, int port, string ipaddress);
    void printrules(vector<rule> &rules);
    void printallowedrules();
    };
