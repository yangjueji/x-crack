/*

Copyright (c) 2017 xsec.io

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THEq
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/

package util

import (
	"fmt"
	"net"
	"regexp"
	"x-crack/logger"
	"x-crack/models"
	"x-crack/vars"

	"bufio"
	"os"
	"strconv"
	"strings"
)

func Hosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

//  http://play.golang.org/p/m8TNTtygK0
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ReadIpList(fileName string) (ipList []models.IpAddr) {
	ipListFile, err := os.Open(fileName)
	if err != nil {
		logger.Log.Fatalf("Open ip List file err, %v", err)
	}

	defer ipListFile.Close()

	scanner := bufio.NewScanner(ipListFile)
	scanner.Split(bufio.ScanLines)
	portR, _ := regexp.Compile(":\\d+")
	protoR, _ := regexp.Compile("\\|\\w+")

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		ipPort := strings.TrimSpace(line)
		t := strings.Split(ipPort, ":")
		t = strings.Split(t[0], "|")
		cidr := t[0]
		ips := make([]string, 0)
		if strings.Contains(cidr, "/") {
			ips, err = Hosts(cidr)
			if err != nil {
				panic(err)
			}
		} else {
			ips = append(ips, cidr)
		}
		tmpPorts := portR.FindAllString(line, -1)
		tmpProtos := protoR.FindAllString(line, -1)
		ports := make([]int, 0, len(tmpPorts))
		protos := make([]string, 0, len(tmpProtos))
		for _, port := range tmpPorts {
			port = strings.Trim(port, ":")
			intPort, err := strconv.Atoi(port)
			if err != nil {
				panic(err)
			}
			ports = append(ports, intPort)
		}
		for _, proto := range tmpProtos {
			proto = strings.Trim(proto, "|")
			protos = append(protos, proto)
		}
		fmt.Printf("ips %v", ips)
		fmt.Printf("ports %v", ports)
		fmt.Printf("protos %v", protos)
		for _, ip := range ips {
			if len(protos) == 0 && len(ports) == 0 {
				// 无端口无服务名使用所有服务
				for k, v := range vars.PortNames {
					addr := models.IpAddr{Ip: ip, Port: k, Protocol: v}
					ipList = append(ipList, addr)
				}
			} else if len(protos) != 0 && len(ports) != 0 {
				// ip列表中指定了端口对应的服务
				for _, port := range ports {
					for _, proto := range protos {
						protocol := strings.ToUpper(proto)
						if vars.SupportProtocols[protocol] {
							addr := models.IpAddr{Ip: ip, Port: port, Protocol: protocol}
							ipList = append(ipList, addr)
						} else {
							logger.Log.Infof("Not support %v, ignore: %v:%v", protocol, ip, port)
						}
					}
				}
			} else if len(ports) != 0 {
				// 通过端口查服务
				for _, port := range ports {
					protocol, ok := vars.PortNames[port]
					if ok && vars.SupportProtocols[protocol] {
						addr := models.IpAddr{Ip: ip, Port: port, Protocol: protocol}
						ipList = append(ipList, addr)
					}
				}
			} else if len(protos) != 0 {
				// 通过服务名查服务
				for _, proto := range protos {
					protocol := strings.ToUpper(proto)
					port, ok := vars.NamePorts[protocol]
					fmt.Printf("%v %v", port, protocol)
					if ok && vars.SupportProtocols[protocol] {
						addr := models.IpAddr{Ip: ip, Port: port, Protocol: protocol}
						ipList = append(ipList, addr)
					}
				}
			}
		}
	}

	return ipList
}

func ReadUserDict(userDict string) (users []string, err error) {
	file, err := os.Open(userDict)
	if err != nil {
		logger.Log.Fatalf("Open user dict file err, %v", err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		user := strings.TrimSpace(scanner.Text())
		users = append(users, user)
	}
	return users, err
}

func ReadPasswordDict(passDict string) (password []string, err error) {
	file, err := os.Open(passDict)
	if err != nil {
		logger.Log.Fatalf("Open password dict file err, %v", err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		passwd := strings.TrimSpace(scanner.Text())
		password = append(password, passwd)
	}
	password = append(password, "")
	return password, err
}
