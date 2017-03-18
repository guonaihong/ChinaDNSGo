package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type routeIp struct {
	Ip    string
	IpInt uint32
	mask  uint32
}

type RouteList struct {
	r []routeIp
}

type ByIp []routeIp

func (ip ByIp) Len() int      { return len(ip) }
func (ip ByIp) Swap(i, j int) { ip[i], ip[j] = ip[j], ip[i] }

// big ... small
func (ip ByIp) Less(i, j int) bool { return ip[i].IpInt > ip[j].IpInt }

func strIp2Int(ipstr string) (uint32, error) {

	l := 0
	ip := uint32(0)
	for {
		pos := strings.Index(ipstr, ".")
		if pos == -1 {
			pos = len(ipstr)
		}
		b, _ := strconv.Atoi(string([]byte(ipstr[:pos])))
		ip <<= 8
		ip |= uint32(b)
		l++
		if len(ipstr) == pos {
			break
		}
		ipstr = string([]byte(ipstr[pos+1:]))
	}

	if l != 4 {
		return 0, fmt.Errorf("ip format must is xxx.xxx.xxx.xxx")
	}

	return ip, nil
}

func newRouteList(fname string) *RouteList {
	f, err := os.Open(fname)
	if err != nil {
		log.Printf("ERROR: open %s fail:%v\n", fname)
		return nil
	}
	defer f.Close()
	r := bufio.NewReader(f)

	list := &RouteList{}
	lineno := 0
	for {
		line, e := r.ReadString('\n')
		if e == io.EOF {
			break
		}

		if e != nil {
			log.Printf("ERROR: read line fail:%v\n", e)
			return nil
		}

		lineno++
		ls := strings.Split(line, "/")
		if len(ls) != 2 {
			log.Printf("WARN: line format is ip/mask")
			continue
		}
		//log.Printf("line is (%s):first(%s) second(%s)\n", line, ls[0], ls[1])

		ipint, err := strIp2Int(ls[0])
		if err != nil {
			log.Printf("WARN: invalid addr %s in %s:%d:%v\n", ls[0], lineno, ipint)
			continue
		}

		maskBytes := []byte(ls[1])
		if maskBytes[len(maskBytes)-1] == '\n' {
			maskBytes = maskBytes[:len(maskBytes)-1]
		}
		if maskBytes[len(maskBytes)-1] == '\r' {
			maskBytes = maskBytes[:len(maskBytes)-1]
		}
		m, err := strconv.Atoi(string(maskBytes))
		if err != nil {
			log.Printf("WARN: invalid mask %s in %s:%d\n", m, ls[1], err)
			continue
		}

		mask := ^(^(uint32(0)) >> uint32(m))
  
        //log.Printf("line:%v  %v:%v %x %x %x  \n",lineno, ls[0],m, ipint,mask, ipint&mask)

		list.r = append(list.r, routeIp{
			Ip:    string(ls[0]),
			IpInt: ipint,
			mask:  mask})
	}

	sort.Sort(ByIp(list.r))

	return list
}

func (r *RouteList) testIpInList(ip uint32) bool {
	//  data := []int{60, 58, 52, 50, 48, 40, 30, 20, 10}
	//  n := sort.Search(len(data), func(i int) bool {
	//      return data[i] < 51
	//  })
	// out 3

	n := sort.Search(len(r.r), func(i int) bool {
		return r.r[i].IpInt < ip
	})

	//fmt.Println(r.r[n])
	//log.Printf("ip = %x, item = %v %x %x \n", ip,r.r[n].Ip,r.r[n].IpInt,r.r[n].mask )

	if n < len(r.r) {
		route := r.r[n]
		if (route.mask & ip) == route.IpInt {
			return true
		}
	}
	return false
}

func TestnewRouteList() {
	chnroute_file := flag.String("c", "/etc/chinadns/chnroute.txt", "china route list")

	r := newRouteList(*chnroute_file)

	n, _ := strIp2Int("1.0.1.1")
	log.Printf("%v\n", r.testIpInList(n))

	n, _ = strIp2Int("1.0.1.3")
	log.Printf("%v\n", r.testIpInList(n))

	n, _ = strIp2Int("118.27.3.4")
	log.Printf("%v\n", r.testIpInList(n))

	n, _ = strIp2Int("93.46.8.89")
	log.Printf("%v\n", r.testIpInList(n))
}

type chinaDNS struct {
	route *RouteList
	sa    string
}

func newChinaDNS(fname string, sa string) *chinaDNS {
	c := new(chinaDNS)
	c.route = newRouteList(fname)
	if c.route == nil {
		return nil
	}

	c.sa = sa
	return c
}

var dnsAddr []string

func init() {
	//dnsAddr = strings.Split("180.76.76.76,182.254.116.116,208.67.222.222:443,192.168.8.1", ",")
	dnsAddr = strings.Split("180.76.76.76,119.29.29.29,208.67.222.222:443,192.168.8.1", ",")
}

type dnsPacket struct {
	dnsType     string
	packet      []byte
	debugString string
}

func getIp(s string) (uint32, error) {
	a := strings.Split(s, "\t")
	ipStr := a[len(a)-1]
	ip, err := strIp2Int(ipStr)
	if err != nil {
		return 0, fmt.Errorf("ip is %s:%s", ipStr, err)
	}
	return ip, nil
}

func getName(s string) (string) {
	a := strings.Split(s, "\t")
	ipStr := a[0]
	return ipStr
}

func getIpString(s string) (string) {
	a := strings.Split(s, "\t")
	ipStr := a[len(a)-1]
	return ipStr
}

func getParameter(localBuf []byte) (string){

   
   s := "" 
   i := 0
   for {
     c := localBuf[i]

     if (c == 0) || (i>80) {
     	return s
     }
    
    printable := false
    if (c >= 'a') && (c<='z'){
      printable = true
    }
    if (c >= 'A') && (c<='Z'){
      printable = true
    }
    if (c >= '1') && (c<='9'){
      printable = true
    }


     tc := string(c)
     if (printable == false) {
       tc = "."
     }
     
     s = s + tc
     i = i + 1

   }

   return s

}

func (c chinaDNS) selectPacket(conn *net.UDPConn, remoteAddr *net.UDPAddr, localBuf []byte) {


    inputPara := getParameter(localBuf[13:])

	packet := make(chan dnsPacket, len(dnsAddr))
	timeout := make(chan bool, 1)
	for _, dnsA := range dnsAddr {



		go func(dnsA string) {
			pos := strings.Index(dnsA, ":")
			dnsB := dnsA
			if pos == -1 {
				dnsA += ":53"
			}else {
			  dnsB = dnsA[:pos]	
			}

            ti, err := strIp2Int(dnsB)
			is_chn_dns_server := c.route.testIpInList(ti)

			addr, err := net.ResolveUDPAddr("udp", dnsA)
			if err != nil {
				log.Printf("Can't resolve address: %v", err)
				return
			}

			cliConn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				log.Printf("Can't dial: ", err)
				return
			}
			defer cliConn.Close()

			// todo set timeout
			_, err = cliConn.Write(localBuf)
			remoteBuf := make([]byte, 1024)
			cliConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err = cliConn.Read(remoteBuf)
			if err != nil {
				//log.Printf("read udp fail: %s %v\n",inputPara, err)
				return
			}

			m := new(dns.Msg)
			err = m.Unpack(remoteBuf)
			if err != nil {
				log.Printf("ERROR: dns server addr is (%s) errmsg is (%s)\n", dnsAddr, err)
				return
			}

			if len(m.Answer) == 0 {
				//log.Printf("WARN: answer size is 0 from %s for %s \n",dnsA,inputPara)
				return 
			}

			flag := false
			debugString := ""
			isCname := true
			for i, v := range m.Answer {
                 
                debugString = "Server:" + dnsA + " | "+inputPara +  "->" + getIpString(v.String()) 

				ip, err := getIp(v.String())
				if err != nil {

					//log.Printf("ERROR: get ip error:%s:String(%s)\n", err, v.String())
					
					continue
				}

				isCname = false

				//debugString = "Server:" + dnsA + " | "+inputPara +  "->" + getIpString(v.String()) 
				//log.Printf("##%d##(server :%#v) (result :%#v %#v)\n", i, dnsA, getName(v.String()),getIpString(v.String()) )
				if flag == false {
					if flag = c.route.testIpInList(ip); flag == true {

						break
					}
				}

				if i>2 {

				}
			}

			if flag {
				// this is a china ip 
				
				// if (dnsAddr[0] == dnsB) || (dnsAddr[1] == dnsB) {
				//   packet <- dnsPacket{"chinese", remoteBuf, debugString}
			 //    }

			 //    if ((dnsAddr[2] == dnsB) || (dnsAddr[3] == dnsB)){
				//   packet <- dnsPacket{"chinese", remoteBuf, debugString}
			 //    }
                if is_chn_dns_server {
                  packet <- dnsPacket{"chinese", remoteBuf, debugString}	
                } else {
                  log.Printf("ignore chn ip %v\n", debugString )
			
                  //packet <- dnsPacket{"chinese", remoteBuf, debugString}
                }



			} else {
      
                 // this is not a china ip
                 
                if (is_chn_dns_server == true) {
                  // only process domestic dns return CNAME case. ignore Class A case
                  if (isCname == true) {
				    packet <- dnsPacket{"cname", remoteBuf, debugString}
				  }else{
				  	log.Printf("ignore oversea ip %v\n", debugString )
				  } 


			    }else{  


				  if (isCname == true) {
				    packet <- dnsPacket{"cname", remoteBuf, debugString}
				  }else{
				  packet <- dnsPacket{"oversea", remoteBuf, debugString}
				  }
			    }
			}
		}(dnsA)
	}

	go func() {
		time.Sleep(time.Second * 1)
		timeout <- true
	}()
	p := dnsPacket{}
	select {

	case p = <-packet:
		

		log.Printf("[%s] %s\n",p.dnsType, p.debugString)

	    conn.WriteToUDP(p.packet, remoteAddr)

	    return

	case <-timeout:
		log.Printf("Query %s timeout!\n",inputPara)
		return
	}
	
}

func (c chinaDNS) handleClient(conn *net.UDPConn) {

	localBuf := make([]byte, 1024)
	n, remoteAddr, err := conn.ReadFromUDP(localBuf)
	if err != nil {
		fmt.Println("ERROR: failed to read UDP msg because of ", err.Error())
		return
	}

	//log.Printf("DEBUG: read local udp data %d\n", n)
	if n>2 {}

	go func() {
		c.selectPacket(conn, remoteAddr, localBuf)
	}()
}

func (c chinaDNS) updServe() {
	addr, err := net.ResolveUDPAddr("udp", c.sa)
	if err != nil {
		log.Printf("ERROR: Cant't resolve address:%v\n", err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("ERROR: listeing fail:%v\n", err)
		return
	}

	defer conn.Close()
	for {
		c.handleClient(conn)
	}
}

func main() {
   

	sa := flag.String("sa", ":53", "dns addr:port")
	fname := flag.String("fn", "/etc/chinadns/chnroute.txt", "china route list")
	ds := flag.String("ds", "", "dns server address")
	flag.Parse()

	if *ds != "" {
		dnsAddr = []string{*ds}
	}

	c := newChinaDNS(*fname, *sa)
	if c == nil {
		return
	}
	c.updServe()
	
	//TestnewRouteList()
}
