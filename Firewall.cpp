#include <iostream>
#include <vector>
#include <string>
#include "Firewall.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
using namespace std;

bool compare(record &r1, record &r2)
{
  if(r1.ipstart<=r2.ipstart)
  {
    return r1.ipend<r2.ipend;
  }
  else
  {
    return false;
  }
}
Firewall::Firewall(string path)
{
    ifstream fs;
    fs.open(path);
    string s;
    while(getline(fs,s))
    {
      push_record(s);
    }
    sort(inboundUdp.begin(),inboundUdp.end(),compare);
    sort(inboundTcp.begin(),inboundTcp.end(),compare);
    sort(outboundUdp.begin(),outboundUdp.end(),compare);
    sort(outboundTcp.begin(),outboundTcp.end(),compare);
}
void Firewall::push_record(string &s)
{
  stringstream line(s);
  string dir="";
  string protocol="";
  string ports="";
  string ips="";
  record r;
  getline(line,dir,',');
  getline(line,protocol,',');
  getline(line,ports,',');

  if(ports.find('-')!=string::npos){
    string p;
    stringstream ss(ports);
    getline(ss,p,'-');
    r.startport=stoi(p);
    getline(ss,p,'-');
    r.endport=stoi(p);
  }else
  {
    r.startport=stoi(ports);
    r.endport=stoi(ports);
  }

  getline(line,ips,',');

  if(ips.find('-')!=string::npos){
    stringstream ss(ips);
    getline(ss,r.ipstart,'-');
    getline(ss,r.ipend,'-');
  }else
  {
    r.ipstart=ips;
    r.ipend=ips;
  }

    if(dir=="inbound" && protocol=="udp") inboundUdp.push_back(r);
    if(dir=="inbound" && protocol=="tcp") inboundTcp.push_back(r);
    if(dir=="outbound" && protocol=="tcp") outboundTcp.push_back(r);
    if(dir=="outbound" && protocol=="udp") outboundUdp.push_back(r);

}
bool Firewall::accept_packet(string dir, string protocol, int port, string ipaddress)
{
  if(dir=="inbound" && protocol=="udp") return binarySearch(inboundUdp,port, ipaddress );
  if(dir=="inbound" && protocol=="tcp") return binarySearch(inboundTcp,port, ipaddress );
  if(dir=="outbound" && protocol=="tcp") return binarySearch(outboundTcp,port, ipaddress );
  if(dir=="outbound" && protocol=="udp") return binarySearch(outboundUdp,port, ipaddress );
  else return false;
}

bool Firewall::search(vector<record> &records, int port, string ipaddress)
{
  for(auto &r: records)
  {
    if((r.startport <= port && r.endport >=port) && (r.ipstart <= ipaddress && r.ipend >=ipaddress))
    return true;
  }
  return false;
}
bool Firewall::binarySearch(vector<record> &records, int port, string ipaddress)
{
  int left=0;
  int right=records.size()-1;
  while(left<=right)
  {
    int mid=(left+right)/2;
    record r=records[mid];
    if((r.startport <= port && r.endport >=port) && (r.ipstart <= ipaddress && r.ipend >=ipaddress)) return true;
    if(ipaddress>r.ipend)
    {
      left=mid+1;
    }
    else
    {
      right=mid-1;
    }
  }
  return false;
}
void Firewall::printallowedrules()
{
  printrecords(inboundTcp);
  printrecords(outboundTcp);
  printrecords(inboundUdp);
  printrecords(outboundTcp);
}
void Firewall::printrecords(vector<record> & records)
{
      for(auto &r: records)
      {
        cout << r.startport << " "  << r.endport <<  " "  <<r.ipstart << " "  << r.ipend << endl;
      }
}

int main(){
  string filepath="./Test.csv";
  Firewall fw(filepath);
  cout <<"Is packet allowed? " << (fw.accept_packet("inbound", "udp", 53, "192.168.2.1")?"True":"False") <<  endl;
  cout <<"Is packet allowed? "<< (fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11")?"True":"False") << endl;
  cout <<"Is packet allowed? "<< (fw.accept_packet("inbound", "tcp", 81, "192.168.1.2")?"True":"False")<< endl;
  cout <<"Is packet allowed? "<< (fw.accept_packet("inbound", "udp", 24, "52.12.48.92")?"True":"False") << endl;
  cout <<"Is packet allowed? "<< (fw.accept_packet("outbound", "udp", 324, "53.12.48.92")?"True":"False") << endl;
  cout <<"Is packet allowed? "<< (fw.accept_packet("outbound", "udp", 24, "53.12.48.92") ?"True":"False")<< endl;
  cout <<"Is packet allowed? "<< (fw.accept_packet("outbound", "udp", 624, "55.12.48.92")?"True":"False") << endl;
  cout <<"Is packet allowed? "<< (fw.accept_packet("outbound", "udp", 724, "56.12.48.92")?"True":"False") << endl;
  cout <<"Is packet allowed? "<< (fw.accept_packet("outbound", "udp", 824, "57.12.48.92") ?"True":"False")<< endl;
  cout <<"Is packet allowed? "<< (fw.accept_packet("outbound", "udp", 924, "58.12.48.92")?"True":"False") << endl;
  cout <<"Is packet allowed? "<< (fw.accept_packet("outbound", "udp", 524, "55.12.48.92") ?"True":"False")<< endl;
  cout <<"Is packet allowed? "<< (fw.accept_packet("outbound", "udp", 624, "56.12.48.92") ?"True":"False")<< endl;
  cout <<"Is packet allowed? "<< (fw.accept_packet("outbound", "udp", 724, "57.12.48.92") ?"True":"False")<< endl;
  cout <<"Is packet allowed? "<< (fw.accept_packet("outbound", "udp", 824, "58.12.48.92") ?"True":"False")<< endl;
  //f.printrecords();
  return 0;
}
