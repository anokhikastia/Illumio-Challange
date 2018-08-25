import java.util.HashMap; 
import java.io.IOException; 
import java.io.FileNotFoundException; 
import java.io.BufferedReader;
import java.io.FileReader;

/* Source: https://www.mkyong.com/java/how-to-read-and-parse-csv-file-in-java/ */

public class Firewall {

    HashMap<Integer, Integer> map = new HashMap<Integer, Integer>(); //stores the hashcode. 
    final static int PRIME = 92821; 

    public static void main(String[] args) {
        Firewall f = new Firewall("networkrules.csv");
        boolean test = f.accept_packet("inbound", "tcp",80,"192.168.1.2");
        System.out.println(test);
        System.out.println(f.accept_packet("inbound", "udp", 53, "192.168.2.1"));
        System.out.println(f.accept_packet("outbound", "tcp", 10234, "192.168.10.11"));
        System.out.println(f.accept_packet("inbound", "tcp", 81, "192.168.1.2")); //false 
        System.out.println(f.accept_packet("inbound", "udp", 24, "52.12.48.92")); //false 
    }

    public Firewall(String f) {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(f));
            String line; 
            while ((line = br.readLine()) != null) {
                String[] rule = line.split(",");
                String direction = rule[0];
                String protocol = rule[1];
                String port = rule[2];
                String ip_address = rule[3];
                if (!port.contains("-") && !ip_address.contains("-")) { //no range. 
                    ip_address = ip_address.replace(".", "");
                    Rule r = new Rule(direction, protocol, Integer.parseInt(port), 
                        Long.parseLong(ip_address));
                    map.put(r.getHash(), 1);
                }
                if (port.contains("-") && !ip_address.contains("-")) { //port contains a range. 
                    String[] range = port.split("-");
                    int start = Integer.parseInt(range[0]); 
                    int end = Integer.parseInt(range[1]);
                    addPortRange(start, end, direction, protocol, ip_address);
                }
                if (!port.contains("-") && ip_address.contains("-")) { //ip address contains a range. 
                    String[] range = ip_address.split("-");
                    String start = range[0].replace(".", "");
                    String end = range[1].replace(".", "");
                    long s = Long.parseLong(start);
                    long e = Long.parseLong(end);
                    addIPRange(s, e, direction, protocol, port);
                }
                if (port.contains("-") && ip_address.contains("-")) {
                    String[] range = port.split("-");
                    int start = Integer.parseInt(range[0]); 
                    int end = Integer.parseInt(range[1]);
                    String[] iprange = ip_address.split("-");
                    String ipstart = iprange[0].replace(".", "");
                    String ipend = iprange[1].replace(".", "");
                    long s = Long.parseLong(ipstart);
                    long e = Long.parseLong(ipend);
                    addRanges(start, end, s, e, direction, protocol);
                }
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public void addRanges(int start, int end, long s, long e, String direction, String protocol) {
        for (int i = start; i <= end; i++) { //port
            for (long j = s; j <= e; j++) {  //ip address. 
                Rule r = new Rule(direction, protocol, i, j);
                map.put(r.getHash(), 1);
            }
        }
    }

    public void addIPRange(long s, long e, String direction, String protocol, String port) {
        for (long j = s; j <= e; j++) {
            Rule r = new Rule(direction, protocol, Integer.parseInt(port), j);
            map.put(r.getHash(), 1);
        }
    }

    public void addPortRange(int start, int end, String direction, String protocol, String ip_address) {
        for (int i = start; i <= end; i++) {
            ip_address = ip_address.replace(".", "");
            Rule r = new Rule(direction, protocol, i, Long.parseLong(ip_address));
            map.put(r.getHash(), 1);
        }
    }

    public boolean accept_packet(String direction, String protocol, int port, String ipAddress) {
        String s = Integer.toString(port);
        ipAddress = ipAddress.replace(".", "");
        Long addr = Long.parseLong(ipAddress);
        Rule r = new Rule(direction, protocol, port, addr);
        return map.containsKey(r.getHash()); 
    }

    public class Rule {
        private String direction; 
        private String protocol; 
        private int port; 
        private long ip_address; 
        private int hash; 
        public Rule(String direction, String protocol, int port, long ip_address) {
            this.direction = direction; 
            this.protocol = protocol; 
            this.port = port; 
            this.ip_address = ip_address; 
            this.hash = hashCode(); 
        }
        public String getDirection() {
            return this.direction; 
        }
        public String getprotocol() {
            return this.protocol; 
        }
        public int getPort() {  
            return this.port; 
        }
        public long getip_address() {
            return this.ip_address; 
        }
        public int getHash() {
            return this.hash; 
        }
        @Override
        public boolean equals(Object object) {
            if (this == object) {
                return true;
            }
            if (!(object instanceof Rule)) {
                return false;
            }
            Rule rule = (Rule) object;
            return  direction.equals(rule.direction) && protocol.equals(rule.protocol)
                && port == rule.port && ip_address == rule.ip_address;
        }
        public int hashCode() {
            int directionhash = direction.hashCode();
            int protocolhash = protocol.hashCode(); 
            long l = PRIME * (directionhash + protocolhash + port + ip_address);
            return Long.valueOf(l).hashCode(); 
        }
    }
}