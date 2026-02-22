package main

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type ConnectionMetadata struct {
	LocalPort uint16
	RemoteIP  string
	Protocol  string
}

type ConnectionStats struct {
	DownloadBytes uint64
	UploadBytes   uint64
}

type ConnectionHistory struct {
	History      [10]ConnectionStats
	CurrentIndex int
	LastActivity time.Time
	mu           sync.Mutex
}

var (
	activeConnections = make(map[ConnectionMetadata]*ConnectionHistory)
	connectionsMutex  sync.RWMutex
	portToProcessMap  = make(map[uint16]string)
	processMutex      sync.RWMutex
)

func isVirtual(name string) bool {
	ifPrefixes := []string{"lo", "any", "docker", "br-", "bluetooth", "usbmon", "nflog", "nfqueue"}
	for _, p := range ifPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func hasExternalIPv4(device pcap.Interface) bool {
	for _, addr := range device.Addresses {
		if addr.IP.To4() != nil && !addr.IP.IsLoopback() {
			return true
		}
	}
	return false
}

type InterfaceInfo struct {
	Name string
	IPs  []string
}

func GetNetworkInterfaces() ([]InterfaceInfo, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	var validInterfaces []InterfaceInfo
	for _, dev := range devices {
		if isVirtual(dev.Name) || !hasExternalIPv4(dev) {
			continue
		}
		var ips []string
		for _, addr := range dev.Addresses {
			if addr.IP.To4() != nil && !addr.IP.IsLoopback() {
				ips = append(ips, addr.IP.String())
			}
		}
		validInterfaces = append(validInterfaces, InterfaceInfo{
			Name: dev.Name,
			IPs:  ips,
		})
	}
	return validInterfaces, nil
}

func startStatsTicker() {
	ticker := time.NewTicker(1 * time.Second)
	go func() {
		for range ticker.C {
			now := time.Now()
			connectionsMutex.Lock()
			for key, history := range activeConnections {
				history.mu.Lock()
				if now.Sub(history.LastActivity) > 10*time.Second {
					delete(activeConnections, key)
					history.mu.Unlock()
					continue
				}
				history.CurrentIndex = (history.CurrentIndex + 1) % 10
				history.History[history.CurrentIndex] = ConnectionStats{}
				history.mu.Unlock()
			}
			connectionsMutex.Unlock()
		}
	}()
}

func updateConnectionStats(metadata ConnectionMetadata, isUpload bool, packetSize uint64) {
	connectionsMutex.RLock()
	history, exists := activeConnections[metadata]
	connectionsMutex.RUnlock()
	if !exists {
		connectionsMutex.Lock()
		history, exists = activeConnections[metadata]
		if !exists {
			history = &ConnectionHistory{
				LastActivity: time.Now(),
			}
			activeConnections[metadata] = history
		}
		connectionsMutex.Unlock()
	}
	history.mu.Lock()
	defer history.mu.Unlock()
	history.LastActivity = time.Now()
	if isUpload {
		history.History[history.CurrentIndex].UploadBytes += packetSize
	} else {
		history.History[history.CurrentIndex].DownloadBytes += packetSize
	}
}

func CapturePackets(iface InterfaceInfo) {
	interfaceName := iface.Name
	ipAddr := iface.IPs[0]
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		packetSize := uint64(len(packet.Data()))
		var meta ConnectionMetadata
		var isUpload bool
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue //Ignore non ipv4 packets
		}
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP := ip.SrcIP.String()
		destIP := ip.DstIP.String()
		if srcIP == ipAddr {
			isUpload = true
			meta.RemoteIP = destIP
		} else if destIP == ipAddr {
			isUpload = false
			meta.RemoteIP = srcIP
		} else {
			continue
		}
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			meta.Protocol = "TCP"
			if isUpload {
				meta.LocalPort = uint16(tcp.SrcPort)
			} else {
				meta.LocalPort = uint16(tcp.DstPort)
			}
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			meta.Protocol = "UDP"
			if isUpload {
				meta.LocalPort = uint16(udp.SrcPort)
			} else {
				meta.LocalPort = uint16(udp.DstPort)
			}
		} else {
			continue
		}
		updateConnectionStats(meta, isUpload, packetSize)
	}
}

func readProcNet(portToInode map[uint16]string, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 || len(line) == 0 {
			continue
		}
		fields := strings.Fields(line)
		localAddr := fields[1]
		parts := strings.Split(localAddr, ":")
		portHex := parts[1]
		portDec, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}
		inode := fields[9]
		portToInode[uint16(portDec)] = inode
	}
}

func updateProcessMap() {
	portToInode := make(map[uint16]string)
	readProcNet(portToInode, "/proc/net/tcp")
	readProcNet(portToInode, "/proc/net/udp")
	inodeToPort := make(map[string]uint16)
	for port, inode := range portToInode {
		inodeToPort[inode] = port
	}
	newPortToProcess := make(map[uint16]string)
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		pid := d.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		fdPath := filepath.Join("/proc", pid, "fd")
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			symlinkPath := filepath.Join(fdPath, fd.Name())
			linkTarget, err := os.Readlink(symlinkPath)
			if err != nil {
				continue
			}
			if strings.HasPrefix(linkTarget, "socket:[") && strings.HasSuffix(linkTarget, "]") {
				inode := linkTarget[8 : len(linkTarget)-1]
				if port, exists := inodeToPort[inode]; exists {
					commPath := filepath.Join("/proc", pid, "comm")
					commData, err := os.ReadFile(commPath)
					if err == nil {
						procName := strings.TrimSpace(string(commData))
						newPortToProcess[port] = procName
					}
				}
			}
		}
	}
	processMutex.Lock()
	portToProcessMap = newPortToProcess
	processMutex.Unlock()
}
func startProcessScanner() {
	ticker := time.NewTicker(2 * time.Second)
	go func() {
		for range ticker.C {
			updateProcessMap()
		}
	}()
}
func main() {
	interfaces, err := GetNetworkInterfaces()
	if err != nil {
		return
	}
	startProcessScanner()
	startStatsTicker()
	CapturePackets(interfaces[0])
}
