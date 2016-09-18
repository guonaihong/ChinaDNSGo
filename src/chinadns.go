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
func (ip ByIp) Less(i, j int) bool { return ip[i].Ip > ip[j].Ip }

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
		log.Printf("open %s fail:%v\n", fname)
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
			log.Printf("read line fail:%v\n", e)
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
		m, err := strconv.Atoi(string(maskBytes))
		if err != nil {
			log.Printf("WARN: invalid mask %s in %s:%d\n", ls[1], lineno, m, err)
			continue
		}

		mask := ^(^(uint32(0)) >> uint32(m))
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

	if n < len(r.r) {
		route := r.r[n]
		if ((route.IpInt ^ ip) & route.mask) > 0 {
			return false
		}
		return true
	}
	return false
}

func TestnewRouteList() {
	chnroute_file := flag.String("c", "./chnroute.txt", "china route list")

	r := newRouteList(*chnroute_file)

	n, _ := strIp2Int("1.0.1.1")
	log.Printf("%v\n", r.testIpInList(n))

	n, _ = strIp2Int("1.0.1.3")
	log.Printf("%v\n", r.testIpInList(n))

	n, _ = strIp2Int("1.0.1.4")
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
	dnsAddr = strings.Split("114.114.114.114,223.5.5.5,8.8.8.8,8.8.4.4,208.67.222.222:443,208.67.222.222:5353", ",")
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

func (c chinaDNS) selectPacket(conn *net.UDPConn, remoteAddr *net.UDPAddr, localBuf []byte) {

	packet := make(chan dnsPacket, len(dnsAddr))
	timeout := make(chan bool, 1)
	for _, dnsA := range dnsAddr {
		go func(dnsA string) {
			pos := strings.Index(dnsA, ":")
			if pos == -1 {
				dnsA += ":53"
			}

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
			_, err = cliConn.Read(remoteBuf)
			if err != nil {
				log.Printf("read remote udp msg fail: %v\n", err)
				return
			}

			m := new(dns.Msg)
			err = m.Unpack(remoteBuf)
			if err != nil {
				log.Printf("ERROR: dns server addr is (%s) errmsg is (%s)\n", dnsAddr, err)
				return
			}

			if len(m.Answer) == 0 {
				log.Printf("WARN: answer size is 0:(%#v)\n", m)
			}

			flag := false
			debugString := ""
			for i, v := range m.Answer {
				ip, err := getIp(v.String())
				if err != nil {
					log.Printf("ERROR: get ip error:%s:String(%s)\n", err, v.String())
					continue
				}

				debugString = v.String()
				log.Printf("##%d##(1-->%#v)(2-->%v)(3-->%v)(4-->%s)\n", i, v, v.Header(), v.String(), v.Header().Name)
				if flag == false {
					if flag = c.route.testIpInList(ip); flag == true {
						break
					}
				}
			}

			if flag {
				packet <- dnsPacket{"chinese", remoteBuf, debugString}
			} else {
				for _, v := range m.Answer {
					log.Printf("debug:debugString(%s)(%s)\n", debugString, v)
				}
				packet <- dnsPacket{"other", remoteBuf, debugString}
			}
		}(dnsA)
	}

	go func() {
		time.Sleep(time.Second * 1)
		timeout <- true
	}()
	i := 0
	p := dnsPacket{}
	select {

	case p = <-packet:
		i++
		if p.dnsType == "chinese" {
			break
		}

		if i == len(dnsAddr) {
			break
		}

	case <-timeout:
		log.Printf("timeout\n")
		return
	}
	log.Printf("DEBUG: packet-->dns type(%s) debugString(%s) packet size(%d)\n",
		p.dnsType, p.debugString, len(p.packet))

	conn.WriteToUDP(p.packet, remoteAddr)
}

func (c chinaDNS) handleClient(conn *net.UDPConn) {

	localBuf := make([]byte, 1024)
	n, remoteAddr, err := conn.ReadFromUDP(localBuf)
	if err != nil {
		fmt.Println("failed to read UDP msg because of ", err.Error())
		return
	}

	log.Printf("DEBUG: read local udp data %d\n", n)
	go func() {
		c.selectPacket(conn, remoteAddr, localBuf)
	}()
}

func (c chinaDNS) updServe() {
	addr, err := net.ResolveUDPAddr("udp", c.sa)
	if err != nil {
		log.Printf("Cant't resolve address:%v\n", err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("listeing fail:%v\n", err)
		return
	}

	defer conn.Close()
	for {
		c.handleClient(conn)
	}
}

func main() {
	sa := flag.String("sa", ":53", "dns addr:port")
	fname := flag.String("fn", "./chnroute.txt", "china route list")
	flag.Parse()

	c := newChinaDNS(*fname, *sa)
	if c == nil {
		return
	}
	c.updServe()
}
