// ──────────────────────────────────────────────────────────────────────────────
//  service/service.cpp
//
//  Milestone schedule:
//    M1: structural stubs
//    M4+M5: ServiceDatabase populated, ServiceDetector::identify() ← this
//    (future M5 extension): grabBanner(), parseVersion()
// ──────────────────────────────────────────────────────────────────────────────

#include "service/service.h"

namespace rhs {

// ═════════════════════════════════════════════════════════════════════════════
//  ServiceDatabase
//
//  Design:
//    - Meyer's singleton: initialised once on first call, thread-safe under
//      C++11 (static local variable initialisation is guaranteed atomic).
//    - No file I/O, no external dependencies — the entire table is compiled
//      into the binary.
//    - Sources: IANA well-known ports (0–1023), registered ports (1024–49151),
//      and common unofficial ports widely used in real networks.
//    - lookup() returns "" for unknown ports — never throws.
// ═════════════════════════════════════════════════════════════════════════════

const ServiceDatabase& ServiceDatabase::instance() {
    static ServiceDatabase db;
    return db;
}

ServiceDatabase::ServiceDatabase() {
    // ── IANA well-known ports (0–1023) ────────────────────────────────────
    map_[1]    = "tcpmux";
    map_[7]    = "echo";
    map_[9]    = "discard";
    map_[13]   = "daytime";
    map_[17]   = "qotd";
    map_[19]   = "chargen";
    map_[20]   = "ftp-data";
    map_[21]   = "ftp";
    map_[22]   = "ssh";
    map_[23]   = "telnet";
    map_[25]   = "smtp";
    map_[37]   = "time";
    map_[43]   = "whois";
    map_[49]   = "tacacs";
    map_[53]   = "dns";
    map_[67]   = "dhcp-server";
    map_[68]   = "dhcp-client";
    map_[69]   = "tftp";
    map_[70]   = "gopher";
    map_[79]   = "finger";
    map_[80]   = "http";
    map_[88]   = "kerberos";
    map_[102]  = "iso-tsap";
    map_[110]  = "pop3";
    map_[111]  = "rpcbind";
    map_[113]  = "ident";
    map_[119]  = "nntp";
    map_[123]  = "ntp";
    map_[135]  = "msrpc";
    map_[137]  = "netbios-ns";
    map_[138]  = "netbios-dgm";
    map_[139]  = "netbios-ssn";
    map_[143]  = "imap";
    map_[161]  = "snmp";
    map_[162]  = "snmp-trap";
    map_[179]  = "bgp";
    map_[194]  = "irc";
    map_[199]  = "smux";
    map_[389]  = "ldap";
    map_[443]  = "https";
    map_[444]  = "snpp";
    map_[445]  = "smb";
    map_[465]  = "smtps";
    map_[500]  = "isakmp";
    map_[502]  = "modbus";
    map_[512]  = "rexec";
    map_[513]  = "rlogin";
    map_[514]  = "rsh";
    map_[515]  = "printer";
    map_[520]  = "rip";
    map_[521]  = "ripng";
    map_[554]  = "rtsp";
    map_[587]  = "smtp-submission";
    map_[593]  = "http-rpc";
    map_[631]  = "ipp";
    map_[636]  = "ldaps";
    map_[646]  = "ldp";
    map_[873]  = "rsync";
    map_[902]  = "vmware-auth";
    map_[989]  = "ftps-data";
    map_[990]  = "ftps";
    map_[993]  = "imaps";
    map_[995]  = "pop3s";

    // ── IANA registered ports (1024–49151) ────────────────────────────────
    map_[1080]  = "socks";
    map_[1194]  = "openvpn";
    map_[1433]  = "mssql";
    map_[1434]  = "mssql-monitor";
    map_[1521]  = "oracle";
    map_[1723]  = "pptp";
    map_[1883]  = "mqtt";
    map_[2049]  = "nfs";
    map_[2181]  = "zookeeper";
    map_[2375]  = "docker";
    map_[2376]  = "docker-tls";
    map_[2379]  = "etcd";
    map_[2380]  = "etcd-peer";
    map_[3000]  = "grafana";
    map_[3128]  = "squid-proxy";
    map_[3268]  = "msft-gc";
    map_[3269]  = "msft-gc-ssl";
    map_[3306]  = "mysql";
    map_[3389]  = "rdp";
    map_[3690]  = "svn";
    map_[4369]  = "epmd";
    map_[4444]  = "krb524";
    map_[4505]  = "saltstack";
    map_[4506]  = "saltstack-ret";
    map_[4789]  = "vxlan";
    map_[4848]  = "glassfish";
    map_[5000]  = "upnp";
    map_[5432]  = "postgresql";
    map_[5601]  = "kibana";
    map_[5672]  = "amqp";
    map_[5900]  = "vnc";
    map_[5984]  = "couchdb";
    map_[6379]  = "redis";
    map_[6380]  = "redis-tls";
    map_[6443]  = "kubernetes-api";
    map_[7001]  = "weblogic";
    map_[7077]  = "spark-master";
    map_[7474]  = "neo4j-browser";
    map_[7687]  = "neo4j-bolt";
    map_[8080]  = "http-alt";
    map_[8081]  = "http-alt2";
    map_[8082]  = "http-alt3";
    map_[8083]  = "influxdb";
    map_[8086]  = "influxdb-http";
    map_[8088]  = "riak-pb";
    map_[8140]  = "puppet";
    map_[8161]  = "activemq-console";
    map_[8180]  = "apache-jk";
    map_[8443]  = "https-alt";
    map_[8500]  = "consul";
    map_[8530]  = "wsus";
    map_[8888]  = "jupyter";
    map_[9000]  = "php-fpm";
    map_[9042]  = "cassandra";
    map_[9090]  = "prometheus";
    map_[9092]  = "kafka";
    map_[9093]  = "kafka-tls";
    map_[9100]  = "jetdirect";
    map_[9200]  = "elasticsearch";
    map_[9300]  = "elasticsearch-node";
    map_[9418]  = "git";
    map_[9999]  = "abyss";
    map_[10000] = "webmin";
    map_[10250] = "kubelet";
    map_[10255] = "kubelet-read";
    map_[11211] = "memcached";
    map_[15672] = "rabbitmq-mgmt";
    map_[16379] = "redis-cluster";
    map_[27017] = "mongodb";
    map_[27018] = "mongodb-shard";
    map_[27019] = "mongodb-config";
    map_[28015] = "rethinkdb";
    map_[29015] = "rethinkdb-cluster";
    map_[50000] = "db2";
}

std::string ServiceDatabase::lookup(uint16_t port) const {
    auto it = map_.find(port);
    return (it != map_.end()) ? it->second : "";
}

bool ServiceDatabase::known(uint16_t port) const {
    return map_.count(port) > 0;
}


// ═════════════════════════════════════════════════════════════════════════════
//  ServiceDetector
// ═════════════════════════════════════════════════════════════════════════════

ServiceDetector::ServiceDetector(int timeoutMs)
    : timeoutMs_(timeoutMs)
{}

// identify()  —  pure port-to-name lookup, O(1), no I/O, thread-safe.
//
// Called from Scanner::postProcess() for every Open result after all
// TCP probes have finished. Because postProcess() is single-threaded
// and ServiceDatabase is a read-only singleton, no locking is needed.
std::string ServiceDetector::identify(uint16_t port) const {
    return ServiceDatabase::instance().lookup(port);
}

std::string ServiceDetector::grabBanner(const std::string& ip,
                                          uint16_t port) const {
    // TODO (future): TCP connect + recv with SO_RCVTIMEO timeout
    (void)ip; (void)port; (void)timeoutMs_;
    return "";
}

std::string ServiceDetector::parseVersion(const std::string& banner,
                                           const std::string& service) const {
    // TODO (future): dispatch to per-protocol parsers
    (void)banner; (void)service;
    return "";
}

std::string ServiceDetector::parseSshVersion(const std::string& banner) const {
    // TODO (future): "SSH-2.0-OpenSSH_8.9p1" → "OpenSSH 8.9p1"
    (void)banner;
    return "";
}

std::string ServiceDetector::parseHttpServer(const std::string& banner) const {
    // TODO (future): "Server: Apache/2.4.54" → "Apache 2.4.54"
    (void)banner;
    return "";
}

std::string ServiceDetector::parseFtpBanner(const std::string& banner) const {
    // TODO (future): "220 ProFTPD 1.3.7" → "ProFTPD 1.3.7"
    (void)banner;
    return "";
}

std::string ServiceDetector::parseSmtpBanner(const std::string& banner) const {
    // TODO (future): "220 ... ESMTP Postfix" → "Postfix"
    (void)banner;
    return "";
}

}  // namespace rhs
